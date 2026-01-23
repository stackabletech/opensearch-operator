//! Controller for [`v1alpha1::OpenSearchCluster`]
//!
//! The cluster specification is validated, Kubernetes resource specifications are created and
//! applied and the cluster status is updated.

use std::{collections::BTreeMap, marker::PhantomData, str::FromStr, sync::Arc};

use apply::Applier;
use build::build;
use dereference::dereference;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cluster_resources::ClusterResourceApplyStrategy,
    commons::{
        affinity::StackableAffinity, networking::DomainName,
        product_image_selection::ResolvedProductImage,
    },
    crd::listener,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service, ServiceAccount},
        policy::v1::PodDisruptionBudget,
        rbac::v1::RoleBinding,
    },
    kube::{Resource, api::ObjectMeta, core::DeserializeGuard, runtime::controller::Action},
    logging::controller::ReconcilerError,
    shared::time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};
use update_status::update_status;
use validate::validate;

use crate::{
    crd::{NodeRoles, v1alpha1},
    framework::{
        HasName, HasUid, NameIsValidLabelValue,
        product_logging::framework::{ValidatedContainerLogConfigChoice, VectorContainerLogConfig},
        role_utils::{GenericProductSpecificCommonConfig, RoleGroupConfig},
        types::{
            common::Port,
            kubernetes::{Hostname, ListenerClassName, NamespaceName, Uid},
            operator::{
                ClusterName, ControllerName, OperatorName, ProductName, ProductVersion,
                RoleGroupName, RoleName,
            },
        },
    },
};

mod apply;
mod build;
mod dereference;
mod update_status;
mod validate;

pub const HTTP_PORT_NAME: &str = "http";
pub const HTTP_PORT: Port = Port(9200);
pub const TRANSPORT_PORT_NAME: &str = "transport";
pub const TRANSPORT_PORT: Port = Port(9300);

/// Names in the controller context which are passed to the submodules of the controller
///
/// The names are not directly defined in [`Context`] because not every submodule requires a
/// Kubernetes client and unit testing is easier without an unnecessary client.
pub struct ContextNames {
    pub product_name: ProductName,
    pub operator_name: OperatorName,
    pub controller_name: ControllerName,
    pub cluster_domain_name: DomainName,
}

/// The controller context
pub struct Context {
    client: stackable_operator::client::Client,
    names: ContextNames,
}

impl Context {
    pub fn new(client: stackable_operator::client::Client, operator_name: OperatorName) -> Self {
        let cluster_domain_name = client.kubernetes_cluster_info.cluster_domain.clone();

        Context {
            client,
            names: Self::context_names(operator_name, cluster_domain_name),
        }
    }

    fn context_names(operator_name: OperatorName, cluster_domain_name: DomainName) -> ContextNames {
        ContextNames {
            product_name: ProductName::from_str("opensearch")
                .expect("should be a valid product name"),
            operator_name,
            controller_name: ControllerName::from_str("opensearchcluster")
                .expect("should be a valid controller name"),
            cluster_domain_name,
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
        #[snafu(source(from(
            stackable_operator::kube::core::error_boundary::InvalidObject,
            Box::new
        )))]
        source: Box<stackable_operator::kube::core::error_boundary::InvalidObject>,
    },

    #[snafu(display("failed to dereference resources"))]
    Dereference { source: dereference::Error },

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

type OpenSearchNodeResources =
    stackable_operator::commons::resources::Resources<v1alpha1::StorageConfig>;

/// Additional objects required for building the cluster
pub struct DereferencedObjects {
    pub maybe_discovery_service_listener: Option<listener::v1alpha1::Listener>,
}

/// Validated [`v1alpha1::OpenSearchConfig`]
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedOpenSearchConfig {
    pub affinity: StackableAffinity,
    pub discovery_service_exposed: bool,
    pub listener_class: ListenerClassName,
    pub logging: ValidatedLogging,
    pub node_roles: NodeRoles,
    pub requested_secret_lifetime: Duration,
    pub resources: OpenSearchNodeResources,
    pub termination_grace_period_seconds: i64,
}

/// Validated log configuration per container
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedLogging {
    pub opensearch_container: ValidatedContainerLogConfigChoice,
    pub vector_container: Option<VectorContainerLogConfig>,
}

impl ValidatedLogging {
    pub fn is_vector_agent_enabled(&self) -> bool {
        self.vector_container.is_some()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedDiscoveryEndpoint {
    pub hostname: Hostname,
    pub port: Port,
}

/// The validated [`v1alpha1::OpenSearchCluster`]
///
/// Validated means that there should be no reason for Kubernetes to reject resources generated
/// from these values. This is usually achieved by using fail-safe types. For instance, the cluster
/// name is wrapped in the type [`ClusterName`]. This type implements e.g. the function
/// [`ClusterName::to_label_value`] which returns a valid label value as string. If this function
/// is used as intended, i.e. to set a label value, and if it is used as late as possible in the
/// call chain, then chances are high that the resulting Kubernetes resource is valid.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedCluster {
    metadata: ObjectMeta,
    pub image: ResolvedProductImage,
    pub product_version: ProductVersion,
    pub name: ClusterName,
    pub namespace: NamespaceName,
    pub uid: Uid,
    pub role_config: v1alpha1::OpenSearchRoleConfig,
    pub role_group_configs: BTreeMap<RoleGroupName, OpenSearchRoleGroupConfig>,
    pub tls_config: v1alpha1::OpenSearchTls,
    pub keystores: Vec<v1alpha1::OpenSearchKeystore>,
    pub discovery_endpoint: Option<ValidatedDiscoveryEndpoint>,
}

impl ValidatedCluster {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        image: ResolvedProductImage,
        product_version: ProductVersion,
        name: ClusterName,
        namespace: NamespaceName,
        uid: impl Into<Uid>,
        role_config: v1alpha1::OpenSearchRoleConfig,
        role_group_configs: BTreeMap<RoleGroupName, OpenSearchRoleGroupConfig>,
        tls_config: v1alpha1::OpenSearchTls,
        keystores: Vec<v1alpha1::OpenSearchKeystore>,
        discovery_endpoint: Option<ValidatedDiscoveryEndpoint>,
    ) -> Self {
        let uid = uid.into();
        Self {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(uid.to_string()),
                ..ObjectMeta::default()
            },
            image,
            product_version,
            name,
            namespace,
            uid,
            role_config,
            role_group_configs,
            tls_config,
            keystores,
            discovery_endpoint,
        }
    }

    /// Returns the one role name
    pub fn role_name() -> RoleName {
        RoleName::from_str("nodes").expect("should be a valid role name")
    }

    /// Returns true if only a single OpenSearch node is defined in the cluster
    pub fn is_single_node(&self) -> bool {
        self.node_count() == 1
    }

    /// Returns the sum of the replicas in all role-groups
    pub fn node_count(&self) -> u32 {
        self.role_group_configs
            .values()
            .map(|rg| rg.replicas as u32)
            .sum()
    }

    /// Returns all role-group configurations which contain the given node role
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

impl HasName for ValidatedCluster {
    fn to_name(&self) -> String {
        self.name.to_string()
    }
}

impl HasUid for ValidatedCluster {
    fn to_uid(&self) -> Uid {
        self.uid.clone()
    }
}

impl NameIsValidLabelValue for ValidatedCluster {
    fn to_label_value(&self) -> String {
        self.name.to_label_value()
    }
}

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

/// Marker for prepared Kubernetes resources which are not applied yet
struct Prepared;
/// Marker for applied Kubernetes resources
struct Applied;

/// List of all Kubernetes resources produced by this controller
///
/// `T` is a marker that indicates if these resources are only [`Prepared`] or already [`Applied`].
/// The marker is useful e.g. to ensure that the cluster status is updated based on the applied
/// resources.
struct KubernetesResources<T> {
    stateful_sets: Vec<StatefulSet>,
    services: Vec<Service>,
    listeners: Vec<listener::v1alpha1::Listener>,
    config_maps: Vec<ConfigMap>,
    service_accounts: Vec<ServiceAccount>,
    role_bindings: Vec<RoleBinding>,
    pod_disruption_budgets: Vec<PodDisruptionBudget>,
    status: PhantomData<T>,
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

/// Reconcile function of the OpenSearchCluster controller
///
/// The reconcile function performs the following steps:
/// 1. Validate the given cluster specification and return a [`ValidatedCluster`] if successful.
/// 2. Build Kubernetes resource specifications from the validated cluster.
/// 3. Apply the Kubernetes resource specifications
/// 4. Update the cluster status
pub async fn reconcile(
    object: Arc<DeserializeGuard<v1alpha1::OpenSearchCluster>>,
    context: Arc<Context>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let cluster = object
        .0
        .as_ref()
        .map_err(stackable_operator::kube::core::error_boundary::InvalidObject::clone)
        .context(DeserializeClusterDefinitionSnafu)?;

    // dereference (client required)
    let dereferenced_objects = dereference(&context.client, cluster)
        .await
        .context(DereferenceSnafu)?;

    // validate (no client required)
    let validated_cluster =
        validate(&context.names, cluster, &dereferenced_objects).context(ValidateClusterSnafu)?;

    // build (no client required; infallible)
    let prepared_resources = build(&context.names, validated_cluster.clone());

    // apply (client required)
    let apply_strategy = ClusterResourceApplyStrategy::from(&cluster.spec.cluster_operation);
    let applied_resources = Applier::new(
        &context.client,
        &context.names,
        &validated_cluster.name,
        &validated_cluster.namespace,
        &validated_cluster.uid,
        apply_strategy,
        &cluster.spec.object_overrides,
    )
    .apply(prepared_resources)
    .await
    .context(ApplyResourcesSnafu)?;

    // not necessary in this controller: create discovery ConfigMap based on the applied resources (client required)

    // update status (client required)
    update_status(&context.client, &context.names, cluster, applied_resources)
        .await
        .context(UpdateStatusSnafu)?;

    Ok(Action::await_change())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        str::FromStr,
    };

    use stackable_operator::{
        commons::{
            affinity::StackableAffinity, networking::DomainName,
            product_image_selection::ResolvedProductImage,
        },
        k8s_openapi::api::core::v1::PodTemplateSpec,
        kvp::LabelValue,
        product_logging::spec::AutomaticContainerLogConfig,
        shared::time::Duration,
    };
    use uuid::uuid;

    use super::{Context, OpenSearchRoleGroupConfig, ValidatedCluster, ValidatedLogging};
    use crate::{
        controller::{OpenSearchNodeResources, ValidatedOpenSearchConfig},
        crd::{NodeRoles, v1alpha1},
        framework::{
            builder::pod::container::EnvVarSet,
            product_logging::framework::ValidatedContainerLogConfigChoice,
            role_utils::GenericProductSpecificCommonConfig,
            types::{
                kubernetes::{ListenerClassName, NamespaceName},
                operator::{ClusterName, OperatorName, ProductVersion, RoleGroupName},
            },
        },
    };

    #[test]
    fn test_context_names() {
        // Test that the function does not panic
        Context::context_names(
            OperatorName::from_str_unsafe("my-operator"),
            DomainName::from_str("cluster.local").expect("should be a valid domain name"),
        );
    }

    #[test]
    fn test_validated_cluster_role_name() {
        // Test that the function does not panic
        ValidatedCluster::role_name();
    }

    #[test]
    fn test_validated_cluster_is_single_node() {
        let validated_cluster = validated_cluster();

        assert!(!validated_cluster.is_single_node());
    }

    #[test]
    fn test_validated_cluster_node_count() {
        let validated_cluster = validated_cluster();

        assert_eq!(18, validated_cluster.node_count());
    }

    #[test]
    fn test_validated_cluster_role_group_configs_filtered_by_node_role() {
        let validated_cluster = validated_cluster();

        assert_eq!(
            BTreeMap::from([
                (
                    RoleGroupName::from_str_unsafe("data1"),
                    role_group_config(
                        4,
                        &[
                            v1alpha1::NodeRole::Ingest,
                            v1alpha1::NodeRole::Data,
                            v1alpha1::NodeRole::RemoteClusterClient,
                        ],
                    ),
                ),
                (
                    RoleGroupName::from_str_unsafe("data2"),
                    role_group_config(
                        6,
                        &[
                            v1alpha1::NodeRole::Ingest,
                            v1alpha1::NodeRole::Data,
                            v1alpha1::NodeRole::RemoteClusterClient,
                        ],
                    ),
                ),
            ]),
            validated_cluster.role_group_configs_filtered_by_node_role(&v1alpha1::NodeRole::Data)
        );
    }

    fn validated_cluster() -> ValidatedCluster {
        ValidatedCluster::new(
            ResolvedProductImage {
                product_version: "3.1.0".to_owned(),
                app_version_label_value: LabelValue::from_str("3.1.0-stackable0.0.0-dev")
                    .expect("should be a valid label value"),
                image: "oci.stackable.tech/sdp/opensearch:3.1.0-stackable0.0.0-dev".to_string(),
                image_pull_policy: "Always".to_owned(),
                pull_secrets: None,
            },
            ProductVersion::from_str_unsafe("3.1.0"),
            ClusterName::from_str_unsafe("my-opensearch"),
            NamespaceName::from_str_unsafe("default"),
            uuid!("e6ac237d-a6d4-43a1-8135-f36506110912"),
            v1alpha1::OpenSearchRoleConfig::default(),
            [
                (
                    RoleGroupName::from_str_unsafe("coordinating"),
                    role_group_config(5, &[v1alpha1::NodeRole::CoordinatingOnly]),
                ),
                (
                    RoleGroupName::from_str_unsafe("cluster-manager"),
                    role_group_config(3, &[v1alpha1::NodeRole::ClusterManager]),
                ),
                (
                    RoleGroupName::from_str_unsafe("data1"),
                    role_group_config(
                        4,
                        &[
                            v1alpha1::NodeRole::Ingest,
                            v1alpha1::NodeRole::Data,
                            v1alpha1::NodeRole::RemoteClusterClient,
                        ],
                    ),
                ),
                (
                    RoleGroupName::from_str_unsafe("data2"),
                    role_group_config(
                        6,
                        &[
                            v1alpha1::NodeRole::Ingest,
                            v1alpha1::NodeRole::Data,
                            v1alpha1::NodeRole::RemoteClusterClient,
                        ],
                    ),
                ),
            ]
            .into(),
            v1alpha1::OpenSearchTls::default(),
            vec![],
            None,
        )
    }

    fn role_group_config(
        replicas: u16,
        node_roles: &[v1alpha1::NodeRole],
    ) -> OpenSearchRoleGroupConfig {
        OpenSearchRoleGroupConfig {
            replicas,
            config: ValidatedOpenSearchConfig {
                affinity: StackableAffinity::default(),
                discovery_service_exposed: true,
                listener_class: ListenerClassName::from_str_unsafe("external-stable"),
                logging: ValidatedLogging {
                    opensearch_container: ValidatedContainerLogConfigChoice::Automatic(
                        AutomaticContainerLogConfig::default(),
                    ),
                    vector_container: None,
                },
                node_roles: NodeRoles(node_roles.to_vec()),
                requested_secret_lifetime: Duration::from_str("1d")
                    .expect("should be a valid duration"),
                resources: OpenSearchNodeResources::default(),
                termination_grace_period_seconds: 120,
            },
            config_overrides: HashMap::default(),
            env_overrides: EnvVarSet::default(),
            cli_overrides: BTreeMap::default(),
            pod_overrides: PodTemplateSpec::default(),
            product_specific_common_config: GenericProductSpecificCommonConfig::default(),
        }
    }
}
