use std::{collections::BTreeMap, marker::PhantomData, str::FromStr, sync::Arc};

use apply::Applier;
use build::build;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cluster_resources::ClusterResourceApplyStrategy,
    commons::{affinity::StackableAffinity, product_image_selection::ProductImage},
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service, ServiceAccount},
        policy::v1::PodDisruptionBudget,
        rbac::v1::RoleBinding,
    },
    kube::{Resource, api::ObjectMeta, core::DeserializeGuard, runtime::controller::Action},
    logging::controller::ReconcilerError,
    role_utils::GenericRoleConfig,
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};
use update_status::update_status;
use validate::validate;

use crate::{
    crd::{
        NodeRoles,
        v1alpha1::{self},
    },
    framework::{
        ClusterName, ControllerName, HasNamespace, HasObjectName, HasUid, IsLabelValue,
        OperatorName, ProductName, ProductVersion, RoleGroupName, RoleName,
        role_utils::{GenericProductSpecificCommonConfig, RoleGroupConfig},
    },
};

mod apply;
mod build;
mod update_status;
mod validate;

pub struct ContextNames {
    pub product_name: ProductName,
    pub operator_name: OperatorName,
    pub controller_name: ControllerName,
}

pub struct Context {
    client: stackable_operator::client::Client,
    names: ContextNames,
}

impl Context {
    pub fn new(client: stackable_operator::client::Client, operator_name: OperatorName) -> Self {
        Context {
            client,
            names: ContextNames {
                product_name: ProductName::from_str("opensearch")
                    .expect("should be a valid product name"),
                operator_name,
                controller_name: ControllerName::from_str("opensearchcluster")
                    .expect("should be a valid controller name"),
            },
        }
    }

    pub fn full_controller_name(&self) -> String {
        format!(
            "{}.{}",
            self.names.controller_name, self.names.operator_name
        )
    }
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to deserialize cluster definition"))]
    DeserializeClusterDefinition {
        // boxed because otherwise Clippy warns about a large enum variant
        source: Box<stackable_operator::kube::core::error_boundary::InvalidObject>,
    },

    #[snafu(display("failed to validate cluster"))]
    ValidateCluster { source: validate::Error },

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

type OpenSearchRoleGroupConfig =
    RoleGroupConfig<GenericProductSpecificCommonConfig, ValidatedOpenSearchConfig>;

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedOpenSearchConfig {
    pub affinity: StackableAffinity,
    pub node_roles: NodeRoles,
    pub resources: stackable_operator::commons::resources::Resources<v1alpha1::StorageConfig>,
    pub termination_grace_period_seconds: i64,
}

// validated and converted to validated and safe types
// no user errors
// not restricted by CRD compliance
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedCluster {
    metadata: ObjectMeta,
    pub image: ProductImage,
    pub product_version: ProductVersion,
    pub name: ClusterName,
    pub namespace: String,
    pub uid: String,
    pub role_config: GenericRoleConfig,
    // "validated" means that labels are valid and no ugly rolegroup name broke them
    pub role_group_configs: BTreeMap<RoleGroupName, OpenSearchRoleGroupConfig>,
}

impl ValidatedCluster {
    pub fn role_name() -> RoleName {
        RoleName::from_str("nodes").expect("should be a valid role name")
    }

    pub fn is_single_node(&self) -> bool {
        self.node_count() == 1
    }

    pub fn node_count(&self) -> u32 {
        self.role_group_configs
            .values()
            .map(|rg| rg.replicas as u32)
            .sum()
    }

    pub fn role_group_configs_filtered_by_node_role(
        &self,
        node_role: &v1alpha1::NodeRole,
    ) -> BTreeMap<RoleGroupName, OpenSearchRoleGroupConfig> {
        self.role_group_configs
            .clone()
            .into_iter()
            .filter(|c| c.1.config.node_roles.contains(node_role))
            .collect()
    }
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
        self.uid.clone()
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
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut stackable_operator::kube::api::ObjectMeta {
        &mut self.metadata
    }
}

pub fn error_policy(
    _object: Arc<DeserializeGuard<v1alpha1::OpenSearchCluster>>,
    error: &Error,
    _context: Arc<Context>,
) -> Action {
    match error {
        // root object is invalid, will be requed when modified
        Error::DeserializeClusterDefinition { .. } => Action::await_change(),
        _ => Action::requeue(*Duration::from_secs(5)),
    }
}

pub async fn reconcile(
    object: Arc<DeserializeGuard<v1alpha1::OpenSearchCluster>>,
    context: Arc<Context>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let cluster = object
        .0
        .as_ref()
        .map_err(stackable_operator::kube::core::error_boundary::InvalidObject::clone)
        .map_err(Box::new)
        .context(DeserializeClusterDefinitionSnafu)?;

    // dereference (client required)

    // validate (no client required)
    let validated_cluster = validate(&context.names, cluster).context(ValidateClusterSnafu)?;

    // build (no client required; infallible)
    let prepared_resources = build(&context.names, validated_cluster.clone());

    // apply (client required)
    let apply_strategy = ClusterResourceApplyStrategy::from(&cluster.spec.cluster_operation);
    let applied_resources = Applier::new(
        &context.client,
        &context.names,
        &validated_cluster,
        apply_strategy,
    )
    .apply(prepared_resources)
    .await
    .context(ApplyResourcesSnafu)?;

    // create discovery ConfigMap based on the applied resources (client required)

    // update status (client required)
    update_status(&context.client, &context.names, cluster, applied_resources)
        .await
        .context(UpdateStatusSnafu)?;

    Ok(Action::await_change())
}

// Marker
struct Prepared;
struct Applied;

struct KubernetesResources<T> {
    stateful_sets: Vec<StatefulSet>,
    services: Vec<Service>,
    config_maps: Vec<ConfigMap>,
    service_accounts: Vec<ServiceAccount>,
    role_bindings: Vec<RoleBinding>,
    pod_disruption_budgets: Vec<PodDisruptionBudget>,
    status: PhantomData<T>,
}
