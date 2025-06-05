use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};

use build::Builder;
use const_format::concatcp;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::product_image_selection::ProductImage,
    k8s_openapi::api::{apps::v1::StatefulSet, core::v1::ObjectReference},
    kube::{
        Resource,
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    kvp::LabelValueError,
    logging::controller::ReconcilerError,
    role_utils::{GenericProductSpecificCommonConfig, GenericRoleConfig, RoleGroup},
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};
use validate::validate;

use crate::{
    OPERATOR_NAME,
    crd::{
        OpenSearchConfigFragment,
        v1alpha1::{self, OpenSearchClusterStatus},
    },
    framework::{AppVersion, RoleGroupName, ToLabelValue},
};

mod build;
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
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to use as label"))]
    InvalidLabelName { source: LabelValueError },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

type RoleGroupConfig = RoleGroup<OpenSearchConfigFragment, GenericProductSpecificCommonConfig>;

struct RoleConfig {
    role_config: GenericRoleConfig,
    role_group_configs: BTreeMap<RoleGroupName, RoleGroupConfig>,
}

// validated and converted to validated and safe types
// no user errors
// not restricted by CRD compliance
pub struct ValidatedCluster {
    origin: v1alpha1::OpenSearchCluster,
    // cluster: v1alpha1::OpenSearchCluster,
    pub image: ProductImage,
    pub product_version: AppVersion,
    pub name: String,
    pub namespace: String,
    pub role_config: GenericRoleConfig,
    // "validated" means that labels are valid and no ugly rolegroup name broke them
    pub role_group_configs: BTreeMap<RoleGroupName, RoleGroupConfig>,
}

impl ToLabelValue for ValidatedCluster {
    fn to_label_value(&self) -> String {
        // opinionated!
        self.origin.to_label_value()
    }
}

// TODO Remove boilerplate
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
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidOpenSearchClusterSnafu)?;

    let client = &ctx.client;

    // ~resolve~ dereference (client required)

    // validate (no client required)
    let validated_cluster = validate(cluster).unwrap();

    // build (no client required; infallible)
    let prepared_resources = Builder::new(validated_cluster).build();

    // apply (client required)
    let cluster_ref = cluster.object_ref(&());
    let apply_strategy = ClusterResourceApplyStrategy::from(&cluster.spec.cluster_operation);
    let applied_resources = apply(client, apply_strategy, &cluster_ref, prepared_resources).await?;

    // update status (client required)
    update_status(client, cluster, applied_resources).await?;

    Ok(Action::await_change())
}

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

async fn apply(
    client: &Client,
    apply_strategy: ClusterResourceApplyStrategy,
    cluster_ref: &ObjectReference,
    resources: Resources<Prepared>,
) -> Result<Resources<Applied>> {
    let mut cluster_resources = ClusterResources::new(
        APP_NAME,
        OPERATOR_NAME,
        CONTROLLER_NAME,
        cluster_ref,
        apply_strategy,
    )
    .context(CreateClusterResourcesSnafu)?;

    let mut applied_resources = Resources::new();
    for stateful_set in resources.stateful_sets {
        let applied_stateful_set = cluster_resources.add(client, stateful_set).await.unwrap();
        applied_resources.stateful_sets.push(applied_stateful_set);
    }

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;

    Ok(applied_resources)
}

async fn update_status(
    client: &Client,
    cluster: &v1alpha1::OpenSearchCluster,
    applied_resources: Resources<Applied>,
) -> Result<()> {
    let mut stateful_set_condition_builder = StatefulSetConditionBuilder::default();
    for stateful_set in applied_resources.stateful_sets {
        stateful_set_condition_builder.add(stateful_set);
    }

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&cluster.spec.cluster_operation);

    let status = OpenSearchClusterStatus {
        conditions: compute_conditions(
            cluster,
            &[
                &stateful_set_condition_builder,
                &cluster_operation_cond_builder,
            ],
        ),
        discovery_hash: None,
    };

    client
        .apply_patch_status(OPERATOR_NAME, cluster, &status)
        .await
        .context(ApplyStatusSnafu)?;

    Ok(())
}
