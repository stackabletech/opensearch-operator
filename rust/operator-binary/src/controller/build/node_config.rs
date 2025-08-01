use serde_json::{Value, json};
use stackable_operator::builder::pod::container::FieldPathEnvVar;

use super::ValidatedCluster;
use crate::{
    controller::OpenSearchRoleGroupConfig,
    crd::v1alpha1,
    framework::{builder::pod::container::EnvVarSet, role_group_utils},
};

pub const CONFIGURATION_FILE_OPENSEARCH_YML: &str = "opensearch.yml";

// TODO Document how to enter config_overrides of various types, e.g. string, list, boolean,
// object, ...

// Configuration file format
//
// This is not well documented.
//
// A list setting can be written as
// - a comma-separated list, e.g.
//   ```
//   setting: a,b,c
//   ```
//   Commas in the values cannot be escaped.
// - a JSON list, e.g.
//   ```
//   setting: ["a", "b", "c"]
//   ```
// - a YAML list, e.g.
//   ```
//   setting:
//     - a
//     - b
//     - c
//   ```
// - a (legacy) flat list, e.g.
//   ```
//   setting.0: a
//   setting.1: b
//   setting.2: b
//   ```

/// type: string
pub const CONFIG_OPTION_CLUSTER_NAME: &str = "cluster.name";

/// type: list of strings
pub const CONFIG_OPTION_DISCOVERY_SEED_HOSTS: &str = "discovery.seed_hosts";

/// type: string
pub const CONFIG_OPTION_DISCOVERY_TYPE: &str = "discovery.type";

/// type: list of strings
pub const CONFIG_OPTION_INITIAL_CLUSTER_MANAGER_NODES: &str =
    "cluster.initial_cluster_manager_nodes";

/// type: string
pub const CONFIG_OPTION_NETWORK_HOST: &str = "network.host";

/// type: string
pub const CONFIG_OPTION_NODE_NAME: &str = "node.name";

/// type: list of strings
pub const CONFIG_OPTION_NODE_ROLES: &str = "node.roles";

/// type: list of strings
pub const CONFIG_OPTION_PLUGINS_SECURITY_NODES_DN: &str = "plugins.security.nodes_dn";

pub struct NodeConfig {
    cluster: ValidatedCluster,
    role_group_config: OpenSearchRoleGroupConfig,
    discovery_service_name: String,
}

// Most functions are public because their configuration values could also be used in environment
// variables.
impl NodeConfig {
    pub fn new(
        cluster: ValidatedCluster,
        role_group_config: OpenSearchRoleGroupConfig,
        discovery_service_name: String,
    ) -> Self {
        Self {
            cluster,
            role_group_config,
            discovery_service_name,
        }
    }

    /// static for the cluster
    pub fn static_opensearch_config(&self) -> String {
        let mut config = serde_json::Map::new();

        config.insert(
            CONFIG_OPTION_CLUSTER_NAME.to_owned(),
            json!(self.cluster.name.to_string()),
        );
        config.insert(
            CONFIG_OPTION_NETWORK_HOST.to_owned(),
            // Bind to all interfaces because the IP address is not known in advance.
            json!("0.0.0.0".to_owned()),
        );
        config.insert(
            CONFIG_OPTION_DISCOVERY_TYPE.to_owned(),
            json!(self.discovery_type()),
        );
        config.insert
             // Accept certificates generated by the secret-operator
             (
                 CONFIG_OPTION_PLUGINS_SECURITY_NODES_DN.to_owned(),
                 json!(["CN=generated certificate for pod".to_owned()]),
             );

        for (setting, value) in self
            .role_group_config
            .config_overrides
            .get(CONFIGURATION_FILE_OPENSEARCH_YML)
            .into_iter()
            .flatten()
        {
            config.insert(setting.to_owned(), json!(value));
        }

        // Ensure a deterministic result
        config.sort_keys();

        Self::to_yaml(config)
    }

    /// different for every node
    pub fn environment_variables(&self) -> EnvVarSet {
        EnvVarSet::new()
            // Set the OpenSearch node name to the Pod name.
            // The node name is used e.g. for `{INITIAL_CLUSTER_MANAGER_NODES}`.
            .with_field_path(CONFIG_OPTION_NODE_NAME, FieldPathEnvVar::Name)
            .with_value(
                CONFIG_OPTION_DISCOVERY_SEED_HOSTS,
                &self.discovery_service_name,
            )
            .with_value(
                CONFIG_OPTION_INITIAL_CLUSTER_MANAGER_NODES,
                self.initial_cluster_manager_nodes(),
            )
            .with_value(
                CONFIG_OPTION_NODE_ROLES,
                self.role_group_config
                    .config
                    .node_roles
                    .iter()
                    .map(|node_role| format!("{node_role}"))
                    .collect::<Vec<_>>()
                    // Node roles cannot contain commas, therefore creating a comma-separated list
                    // is safe.
                    .join(","),
            )
            .with_values(self.role_group_config.env_overrides.clone())
    }

    fn to_yaml(kv: serde_json::Map<String, Value>) -> String {
        kv.iter()
            .map(|(key, value)| format!("{key}: {value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Configuration for `{DISCOVERY_TYPE}`
    ///
    /// "zen" is the default if `{DISCOVERY_TYPE}` is not set.
    /// It is nevertheless explicitly set here.
    /// see <https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/discovery/DiscoveryModule.java#L88-L89>
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
    /// <https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/coordination/ClusterBootstrapService.java#L79-L93>.
    ///
    /// According to
    /// <https://docs.opensearch.org/docs/3.0/install-and-configure/configuring-opensearch/discovery-gateway-settings/>,
    /// it contains "a list of cluster-manager-eligible nodes used to bootstrap the cluster."
    ///
    /// However, the documentation for Elasticsearch is more detailed and contains the following
    /// notes (see <https://www.elastic.co/guide/en/elasticsearch/reference/9.0/modules-discovery-settings.html>):
    /// * Remove this setting once the cluster has formed, and never set it again for this cluster.
    /// * Do not configure this setting on master-ineligible nodes.
    /// * Do not configure this setting on nodes joining an existing cluster.
    /// * Do not configure this setting on nodes which are restarting.
    /// * Do not configure this setting when performing a full-cluster restart.
    ///
    /// The OpenSearch Helm chart only sets master nodes but does not handle the other cases (see
    /// <https://github.com/opensearch-project/helm-charts/blob/opensearch-3.0.0/charts/opensearch/templates/statefulset.yaml#L414-L415>),
    /// so they are also ignored here for the moment.
    fn initial_cluster_manager_nodes(&self) -> String {
        if !self.cluster.is_single_node()
            && self
                .role_group_config
                .config
                .node_roles
                .contains(&v1alpha1::NodeRole::ClusterManager)
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
                let role_group_resource_names = role_group_utils::ResourceNames {
                    cluster_name: self.cluster.name.clone(),
                    role_name: ValidatedCluster::role_name(),
                    role_group_name,
                };

                pod_names.extend(
                    (0..role_group_config.replicas)
                        .map(|i| format!("{}-{i}", role_group_resource_names.stateful_set_name())),
                );
            }
            // Pod names cannot contain commas, therefore creating a comma-separated list is safe.
            pod_names.join(",")
        } else {
            // This setting is not allowed on single node cluster, see
            // <https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/coordination/ClusterBootstrapService.java#L126-L136>
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {

    use std::{
        collections::{BTreeMap, HashMap},
        str::FromStr,
    };

    use stackable_operator::{
        commons::{
            affinity::StackableAffinity, product_image_selection::ProductImage,
            resources::Resources,
        },
        k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, ObjectFieldSelector, PodTemplateSpec},
        kube::api::ObjectMeta,
        role_utils::GenericRoleConfig,
    };

    use super::*;
    use crate::{
        controller::ValidatedOpenSearchConfig,
        crd::NodeRoles,
        framework::{ClusterName, ProductVersion, role_utils::GenericProductSpecificCommonConfig},
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

        let role_group_config = OpenSearchRoleGroupConfig {
            replicas: 1,
            config: ValidatedOpenSearchConfig {
                affinity: StackableAffinity::default(),
                node_roles: NodeRoles::default(),
                resources: Resources::default(),
                termination_grace_period_seconds: 30,
                listener_class: "cluster-internal".to_string(),
            },
            config_overrides: HashMap::default(),
            env_overrides: [("TEST".to_owned(), "value".to_owned())].into(),
            cli_overrides: BTreeMap::default(),
            pod_overrides: PodTemplateSpec::default(),
            product_specific_common_config: GenericProductSpecificCommonConfig::default(),
        };

        let node_config = NodeConfig::new(
            cluster,
            role_group_config,
            "my-opensearch-cluster-manager".to_owned(),
        );

        let env_vars = node_config.environment_variables();

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
                    value: Some("my-opensearch-cluster-manager".to_owned()),
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
