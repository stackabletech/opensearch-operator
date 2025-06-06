use std::{collections::BTreeMap, marker::PhantomData, str::FromStr, sync::Arc};

use apply::apply;
use build::Builder;
use const_format::concatcp;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cluster_resources::ClusterResourceApplyStrategy,
    commons::product_image_selection::ProductImage,
    k8s_openapi::api::apps::v1::StatefulSet,
    kube::{Resource, core::DeserializeGuard, runtime::controller::Action},
    logging::controller::ReconcilerError,
    role_utils::{GenericProductSpecificCommonConfig, GenericRoleConfig, RoleGroup},
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};
use update_status::update_status;
use validate::validate;

use crate::{
    OPERATOR_NAME,
    crd::{
        OpenSearchConfigFragment,
        v1alpha1::{self},
    },
    framework::{
        AppName, AppVersion, ClusterName, ControllerName, HasNamespace, HasObjectName, HasUid,
        IsLabelValue, OperatorName, RoleGroupName, RoleName,
    },
};

mod apply;
mod build;
mod update_status;
mod validate;

const CONTROLLER_NAME: &str = "opensearchcluster";
pub const FULL_CONTROLLER_NAME: &str = concatcp!(CONTROLLER_NAME, '.', OPERATOR_NAME);
const APP_NAME: &str = "opensearch";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("OpenSearchCluster object is invalid"))]
    InvalidOpenSearchCluster {
        // boxed because otherwise Clippy warns about a large enum variant
        source: Box<stackable_operator::kube::core::error_boundary::InvalidObject>,
    },

    #[snafu(display("failed to apply resources"))]
    ApplyResources { source: apply::Error },

    #[snafu(display("failed to update status"))]
    UpdateStatus { source: update_status::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

type RoleGroupConfig = RoleGroup<OpenSearchConfigFragment, GenericProductSpecificCommonConfig>;

// validated and converted to validated and safe types
// no user errors
// not restricted by CRD compliance
#[derive(Clone)]
pub struct ValidatedCluster {
    origin: v1alpha1::OpenSearchCluster,
    pub image: ProductImage,
    pub product_version: AppVersion,
    pub name: ClusterName,
    pub namespace: String,
    pub role_config: GenericRoleConfig,
    // "validated" means that labels are valid and no ugly rolegroup name broke them
    pub role_group_configs: BTreeMap<RoleGroupName, RoleGroupConfig>,
}

impl HasObjectName for ValidatedCluster {
    fn to_object_name(&self) -> String {
        self.name.to_object_name()
    }
}

impl HasNamespace for ValidatedCluster {
    fn to_namespace(&self) -> String {
        self.namespace.clone()
    }
}

impl HasUid for ValidatedCluster {
    fn to_uid(&self) -> String {
        // TODO fix
        self.origin.metadata.uid.clone().unwrap()
    }
}

// ?
impl IsLabelValue for ValidatedCluster {
    fn to_label_value(&self) -> String {
        // opinionated!
        self.name.to_label_value()
    }
}

// TODO Remove boilerplate (like derive_more)
impl Resource for ValidatedCluster {
    type DynamicType =
        <v1alpha1::OpenSearchCluster as stackable_operator::kube::Resource>::DynamicType;
    type Scope = <v1alpha1::OpenSearchCluster as stackable_operator::kube::Resource>::Scope;

    fn kind(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        v1alpha1::OpenSearchCluster::kind(dt)
    }

    fn group(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        v1alpha1::OpenSearchCluster::group(dt)
    }

    fn version(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        v1alpha1::OpenSearchCluster::version(dt)
    }

    fn plural(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        v1alpha1::OpenSearchCluster::plural(dt)
    }

    fn meta(&self) -> &stackable_operator::kube::api::ObjectMeta {
        self.origin.meta()
    }

    fn meta_mut(&mut self) -> &mut stackable_operator::kube::api::ObjectMeta {
        self.origin.meta_mut()
    }
}

pub fn error_policy(
    _obj: Arc<DeserializeGuard<v1alpha1::OpenSearchCluster>>,
    error: &Error,
    _ctx: Arc<Ctx>,
) -> Action {
    match error {
        // root object is invalid, will be requed when modified
        Error::InvalidOpenSearchCluster { .. } => Action::await_change(),
        _ => Action::requeue(*Duration::from_secs(5)),
    }
}

pub async fn reconcile(
    object: Arc<DeserializeGuard<v1alpha1::OpenSearchCluster>>,
    ctx: Arc<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let cluster = object
        .0
        .as_ref()
        .map_err(stackable_operator::kube::core::error_boundary::InvalidObject::clone)
        .map_err(Box::new)
        .context(InvalidOpenSearchClusterSnafu)?;

    let client = &ctx.client;

    // ~resolve~ dereference (client required)

    // validate (no client required)
    let validated_cluster = validate(cluster).unwrap();

    // build (no client required; infallible)
    let prepared_resources = Builder::new(validated_cluster.clone()).build();

    // apply (client required)
    //
    // into controller context!
    let app_name = AppName::from_str(APP_NAME).unwrap();
    let operator_name = OperatorName::from_str(OPERATOR_NAME).unwrap();
    let controller_name = ControllerName::from_str(CONTROLLER_NAME).unwrap();
    let apply_strategy = ClusterResourceApplyStrategy::from(&cluster.spec.cluster_operation);
    let applied_resources = apply(
        client,
        &app_name,
        &operator_name,
        &controller_name,
        &validated_cluster,
        apply_strategy,
        prepared_resources,
    )
    .await
    .context(ApplyResourcesSnafu)?;

    // update status (client required)
    update_status(client, cluster, applied_resources)
        .await
        .context(UpdateStatusSnafu)?;

    Ok(Action::await_change())
}

// Marker
struct Prepared;
struct Applied;

struct Resources<T> {
    stateful_sets: Vec<StatefulSet>,
    status: PhantomData<T>,
}

impl<T> Resources<T> {
    fn new() -> Self {
        Resources {
            stateful_sets: vec![],
            status: PhantomData,
        }
    }
}
