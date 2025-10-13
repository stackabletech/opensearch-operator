//! The build step in the OpenSearchCluster controller

use std::marker::PhantomData;

use role_builder::RoleBuilder;

use super::{ContextNames, KubernetesResources, Prepared, ValidatedCluster};

pub mod node_config;
pub mod product_logging;
pub mod role_builder;
pub mod role_group_builder;

/// Builds Kubernetes resource specifications from the given validated cluster
///
/// This function cannot fail because all failing conditions were already checked in the validation
/// step.
/// A Kubernetes client is not required because references to other Kubernetes resources must
/// already be dereferenced in a prior step and the result would be validated and added to the
/// validated cluster.
pub fn build(names: &ContextNames, cluster: ValidatedCluster) -> KubernetesResources<Prepared> {
    let mut config_maps = vec![];
    let mut stateful_sets = vec![];
    let mut services = vec![];
    let mut listeners = vec![];

    let role_builder = RoleBuilder::new(cluster.clone(), names);

    for role_group_builder in role_builder.role_group_builders() {
        config_maps.push(role_group_builder.build_config_map());
        stateful_sets.push(role_group_builder.build_stateful_set());
        services.push(role_group_builder.build_headless_service());
        listeners.push(role_group_builder.build_listener());
    }

    let cluster_manager_service = role_builder.build_cluster_manager_service();
    services.push(cluster_manager_service);

    let service_accounts = vec![role_builder.build_service_account()];

    let role_bindings = vec![role_builder.build_role_binding()];

    let pod_disruption_budgets = role_builder.build_pdb().into_iter().collect();

    KubernetesResources {
        stateful_sets,
        services,
        listeners,
        config_maps,
        service_accounts,
        role_bindings,
        pod_disruption_budgets,
        status: PhantomData,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        str::FromStr,
    };

    use stackable_operator::{
        commons::{affinity::StackableAffinity, product_image_selection::ResolvedProductImage},
        k8s_openapi::api::core::v1::PodTemplateSpec,
        kube::Resource,
        kvp::LabelValue,
        product_logging::spec::AutomaticContainerLogConfig,
        role_utils::GenericRoleConfig,
    };
    use uuid::uuid;

    use super::build;
    use crate::{
        controller::{
            ContextNames, OpenSearchNodeResources, OpenSearchRoleGroupConfig, ValidatedCluster,
            ValidatedContainerLogConfigChoice, ValidatedLogging, ValidatedOpenSearchConfig,
        },
        crd::{NodeRoles, v1alpha1},
        framework::{
            ClusterName, ControllerName, ListenerClassName, NamespaceName, OperatorName,
            ProductName, ProductVersion, RoleGroupName, builder::pod::container::EnvVarSet,
            role_utils::GenericProductSpecificCommonConfig,
        },
    };

    #[test]
    fn test_build() {
        let resources = build(&context_names(), validated_cluster());

        assert_eq!(
            vec![
                "my-opensearch-nodes-cluster-manager",
                "my-opensearch-nodes-coordinating",
                "my-opensearch-nodes-data",
            ],
            extract_resource_names(&resources.stateful_sets)
        );
        assert_eq!(
            vec![
                "my-opensearch",
                "my-opensearch-nodes-cluster-manager-headless",
                "my-opensearch-nodes-coordinating-headless",
                "my-opensearch-nodes-data-headless"
            ],
            extract_resource_names(&resources.services)
        );
        assert_eq!(
            vec![
                "my-opensearch-nodes-cluster-manager",
                "my-opensearch-nodes-coordinating",
                "my-opensearch-nodes-data"
            ],
            extract_resource_names(&resources.listeners)
        );
        assert_eq!(
            vec![
                "my-opensearch-nodes-cluster-manager",
                "my-opensearch-nodes-coordinating",
                "my-opensearch-nodes-data"
            ],
            extract_resource_names(&resources.config_maps)
        );
        assert_eq!(
            vec!["my-opensearch-serviceaccount"],
            extract_resource_names(&resources.service_accounts)
        );
        assert_eq!(
            vec!["my-opensearch-rolebinding"],
            extract_resource_names(&resources.role_bindings)
        );
        assert_eq!(
            vec!["my-opensearch-nodes"],
            extract_resource_names(&resources.pod_disruption_budgets)
        );
    }

    fn extract_resource_names(resources: &[impl Resource]) -> Vec<&str> {
        let mut resource_names: Vec<&str> = resources
            .iter()
            .filter_map(|resource| resource.meta().name.as_ref())
            .map(|x| x.as_str())
            .collect();
        resource_names.sort();
        resource_names
    }

    fn context_names() -> ContextNames {
        ContextNames {
            product_name: ProductName::from_str_unsafe("opensearch"),
            operator_name: OperatorName::from_str_unsafe("opensearch.stackable.tech"),
            controller_name: ControllerName::from_str_unsafe("opensearchcluster"),
        }
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
            GenericRoleConfig::default(),
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
                    RoleGroupName::from_str_unsafe("data"),
                    role_group_config(
                        8,
                        &[
                            v1alpha1::NodeRole::Ingest,
                            v1alpha1::NodeRole::Data,
                            v1alpha1::NodeRole::RemoteClusterClient,
                        ],
                    ),
                ),
            ]
            .into(),
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
                listener_class: ListenerClassName::from_str_unsafe("external-stable"),
                logging: ValidatedLogging {
                    opensearch_container: ValidatedContainerLogConfigChoice::Automatic(
                        AutomaticContainerLogConfig::default(),
                    ),
                    vector_container: None,
                },
                node_roles: NodeRoles(node_roles.to_vec()),
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
