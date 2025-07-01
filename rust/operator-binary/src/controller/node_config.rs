use std::collections::BTreeMap;

use stackable_operator::builder::pod::container::FieldPathEnvVar;

use super::{OpenSearchRoleGroupConfig, ValidatedCluster};
use crate::{
    crd::{NodeRoles, v1alpha1},
    framework::{RoleName, builder::pod::container::EnvVarSet, to_qualified_role_group_name},
};

pub const CONFIGURATION_FILE_OPENSEARCH_YML: &str = "opensearch.yml";
pub const CONFIG_OPTION_CLUSTER_NAME: &str = "cluster.name";
pub const DISCOVERY_SEED_HOSTS: &str = "discovery.seed_hosts";
pub const DISCOVERY_TYPE: &str = "discovery.type";
pub const INITIAL_CLUSTER_MANAGER_NODES: &str = "cluster.initial_cluster_manager_nodes";
pub const NETWORK_HOST: &str = "network.host";
pub const NODE_NAME: &str = "node.name";
pub const NODE_ROLES: &str = "node.roles";

pub struct NodeConfig {
    role_name: RoleName,
    cluster: ValidatedCluster,
}

// Most functions are public because their configuration values could also be used in environment
// variables.
impl NodeConfig {
    pub fn new(role_name: RoleName, cluster: ValidatedCluster) -> Self {
        Self { role_name, cluster }
    }

    /// static for the cluster
    pub fn static_opensearch_config(
        &self,
        // TODO only config overrides
        role_group_config: &OpenSearchRoleGroupConfig,
    ) -> String {
        let mut config: BTreeMap<String, String> = [
            (CONFIG_OPTION_CLUSTER_NAME.to_owned(), self.cluster_name()),
            (NETWORK_HOST.to_owned(), self.network_host()),
            (DISCOVERY_TYPE.to_owned(), self.discovery_type()),
        ]
        .into();

        config.extend(
            role_group_config
                .config_overrides
                .get(CONFIGURATION_FILE_OPENSEARCH_YML)
                .cloned()
                .unwrap_or_default(),
        );

        NodeConfig::to_yaml(config)
    }

    /// different for every node
    pub fn environment_variables(
        &self,
        // only node roles?
        role_group_config: &OpenSearchRoleGroupConfig,
    ) -> EnvVarSet {
        EnvVarSet::new()
            // Set the OpenSearch node name to the Pod name.
            // The node name is used e.g. for `{INITIAL_CLUSTER_MANAGER_NODES}`.
            .with_field_path(NODE_NAME, FieldPathEnvVar::Name)
            // TODO DISCOVERY_SEED_HOSTS to opensearch.yml?
            .with_value(DISCOVERY_SEED_HOSTS, self.discovery_seed_hosts())
            .with_value(
                INITIAL_CLUSTER_MANAGER_NODES,
                self.initial_cluster_manager_nodes(&role_group_config.config.node_roles),
            )
            .with_value(
                NODE_ROLES,
                self.node_roles(&role_group_config.config.node_roles),
            )
            .with_values(role_group_config.env_overrides.clone())
    }

    fn to_yaml(kv: BTreeMap<String, String>) -> String {
        // TODO Do it right!
        kv.iter()
            .map(|(key, value)| format!("{key}: {value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn cluster_name(&self) -> String {
        self.cluster.name.to_string()
    }

    pub fn discovery_seed_hosts(&self) -> String {
        // TODO Check length
        format!("{}-cluster-manager", self.cluster_name())
    }

    /// Configuration for `{DISCOVERY_TYPE}`
    ///
    /// "zen" is the default if `{DISCOVERY_TYPE}` is not set.
    /// It is nevertheless explicitly set here.
    /// see https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/discovery/DiscoveryModule.java#L88-L89
    ///
    /// "single-node" disables the bootstrap checks, like validating the JVM and discovery
    /// configurations.
    pub fn discovery_type(&self) -> String {
        if self.cluster.is_single_node() {
            "single-node".to_owned()
        } else {
            "zen".to_owned()
        }
    }

    /// Configuration for `cluster.initial_cluster_manager_nodes` which replaces
    /// `cluster.initial_master_nodes`, see
    /// https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/coordination/ClusterBootstrapService.java#L79-L93.
    ///
    /// According to
    /// https://docs.opensearch.org/docs/3.0/install-and-configure/configuring-opensearch/discovery-gateway-settings/,
    /// it contains "a list of cluster-manager-eligible nodes used to bootstrap the cluster."
    ///
    /// However, the documentation for Elasticsearch is more detailed and contains the following
    /// notes (see https://www.elastic.co/guide/en/elasticsearch/reference/9.0/modules-discovery-settings.html):
    /// * Remove this setting once the cluster has formed, and never set it again for this cluster.
    /// * Do not configure this setting on master-ineligible nodes.
    /// * Do not configure this setting on nodes joining an existing cluster.
    /// * Do not configure this setting on nodes which are restarting.
    /// * Do not configure this setting when performing a full-cluster restart.
    ///
    /// The OpenSearch Helm chart only sets master nodes but does not handle the other cases (see
    /// https://github.com/opensearch-project/helm-charts/blob/opensearch-3.0.0/charts/opensearch/templates/statefulset.yaml#L414-L415),
    /// so they are also ignored here for the moment.
    pub fn initial_cluster_manager_nodes(&self, node_roles: &NodeRoles) -> String {
        if !self.cluster.is_single_node()
            && node_roles.contains(&v1alpha1::NodeRole::ClusterManager)
        {
            let cluster_manager_configs = self
                .cluster
                .role_group_configs_filtered_by_node_role(&v1alpha1::NodeRole::ClusterManager);

            // This setting requires node names as set in `{NODE_NAME}`.
            // The node names are set to the pod names with
            // `valueFrom.fieldRef.fieldPath: metadata.name`, so it is okay to calculate the pod
            // names here and use them as node names.
            let mut pod_names = vec![];
            for (role_group_name, role_group_config) in cluster_manager_configs {
                let sts_name = to_qualified_role_group_name(
                    &self.cluster.name,
                    &self.role_name,
                    &role_group_name,
                );
                pod_names
                    .extend((0..role_group_config.replicas).map(|i| format!("{sts_name}-{i}")));
            }
            pod_names.join(",")
        } else {
            // This setting is not allowed on single node cluster, see
            // https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/coordination/ClusterBootstrapService.java#L126-L136
            String::new()
        }
    }

    pub fn network_host(&self) -> String {
        // Bind to all interfaces because the IP address is not known in advance.
        "0.0.0.0".to_owned()
    }

    pub fn node_roles(&self, node_roles: &NodeRoles) -> String {
        node_roles
            .iter()
            .map(|node_role| format!("{node_role}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(test)]
mod tests {

    use std::{collections::HashMap, str::FromStr};

    use stackable_operator::{
        commons::product_image_selection::ProductImage,
        k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, ObjectFieldSelector, PodTemplateSpec},
        kube::api::ObjectMeta,
        role_utils::GenericRoleConfig,
    };

    use super::*;
    use crate::framework::{
        ClusterName, ProductVersion, role_utils::GenericProductSpecificCommonConfig,
    };

    #[test]
    pub fn test_environment_variables() {
        let image: ProductImage = serde_json::from_str(r#"{"productVersion": "3.0.0"}"#)
            .expect("should be a valid ProductImage");
        let cluster = ValidatedCluster {
            metadata: ObjectMeta::default(),
            image: image.clone(),
            product_version: ProductVersion::from_str(image.product_version())
                .expect("should be a valid ProductVersion"),
            name: ClusterName::from_str("my-opensearch-cluster")
                .expect("should be a valid ClusterName"),
            namespace: "default".to_owned(),
            uid: "0b1e30e6-326e-4c1a-868d-ad6598b49e8b".to_owned(),
            role_config: GenericRoleConfig::default(),
            role_group_configs: BTreeMap::new(),
        };
        let role_name = RoleName::from_str("nodes").expect("should be a valid role name");

        let node_config = NodeConfig::new(role_name, cluster);

        let role_group_config = OpenSearchRoleGroupConfig {
            replicas: 1,
            config: v1alpha1::OpenSearchConfig {
                node_roles: NodeRoles::default(),
            },
            config_overrides: HashMap::default(),
            env_overrides: [("TEST".to_owned(), "value".to_owned())].into(),
            cli_overrides: BTreeMap::default(),
            pod_overrides: PodTemplateSpec::default(),
            product_specific_common_config: GenericProductSpecificCommonConfig::default(),
        };

        let env_vars = node_config.environment_variables(&role_group_config);

        // TODO Test EnvVarSet and compare EnvVarSets
        assert_eq!(
            vec![
                EnvVar {
                    name: "TEST".to_owned(),
                    value: Some("value".to_owned()),
                    value_from: None
                },
                EnvVar {
                    name: "cluster.initial_cluster_manager_nodes".to_owned(),
                    value: Some("".to_owned()),
                    value_from: None
                },
                EnvVar {
                    name: "discovery.seed_hosts".to_owned(),
                    value: Some("my-opensearch-cluster-cluster-manager".to_owned()),
                    value_from: None
                },
                EnvVar {
                    name: "node.name".to_owned(),
                    value: None,
                    value_from: Some(EnvVarSource {
                        config_map_key_ref: None,
                        field_ref: Some(ObjectFieldSelector {
                            api_version: None,
                            field_path: "metadata.name".to_owned()
                        }),
                        resource_field_ref: None,
                        secret_key_ref: None
                    })
                },
                EnvVar {
                    name: "node.roles".to_owned(),
                    value: Some("".to_owned()),
                    value_from: None
                }
            ],
            <EnvVarSet as Into<Vec<EnvVar>>>::into(env_vars)
        );
    }
}
