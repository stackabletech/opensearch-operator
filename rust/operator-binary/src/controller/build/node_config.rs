//! Configuration of an OpenSearch node

use std::str::FromStr;

use serde_json::{Value, json};
use stackable_operator::builder::pod::container::FieldPathEnvVar;

use super::ValidatedCluster;
use crate::{
    controller::OpenSearchRoleGroupConfig,
    crd::v1alpha1,
    framework::{
        builder::pod::container::{EnvVarName, EnvVarSet},
        role_group_utils,
        types::{kubernetes::ServiceName, operator::RoleGroupName},
    },
};

/// The main configuration file of OpenSearch
pub const CONFIGURATION_FILE_OPENSEARCH_YML: &str = "opensearch.yml";

/// The cluster name.
/// Type: string
pub const CONFIG_OPTION_CLUSTER_NAME: &str = "cluster.name";

/// The list of hosts that perform discovery when a node is started.
/// Type: (comma-separated) list of strings
pub const CONFIG_OPTION_DISCOVERY_SEED_HOSTS: &str = "discovery.seed_hosts";

/// By default, OpenSearch forms a multi-node cluster. Set `discovery.type` to `single-node` to
/// form a single-node cluster.
/// Type: string
pub const CONFIG_OPTION_DISCOVERY_TYPE: &str = "discovery.type";

/// A list of cluster-manager-eligible nodes used to bootstrap the cluster.
/// Type: (comma-separated) list of strings
pub const CONFIG_OPTION_INITIAL_CLUSTER_MANAGER_NODES: &str =
    "cluster.initial_cluster_manager_nodes";

/// Binds an OpenSearch node to an address.
/// Type: string
pub const CONFIG_OPTION_NETWORK_HOST: &str = "network.host";

/// The custom node attribute "role-group"
/// Type: string
pub const CONFIG_OPTION_NODE_ATTR_ROLE_GROUP: &str = "node.attr.role-group";

/// A descriptive name for the node.
/// Type: string
pub const CONFIG_OPTION_NODE_NAME: &str = "node.name";

/// Defines one or more roles for an OpenSearch node.
/// Type: (comma-separated) list of strings
pub const CONFIG_OPTION_NODE_ROLES: &str = "node.roles";

/// Specifies a list of distinguished names (DNs) that denote the other nodes in the cluster.
/// Type: (comma-separated) list of strings
pub const CONFIG_OPTION_PLUGINS_SECURITY_NODES_DN: &str = "plugins.security.nodes_dn";

/// Whether to enable TLS on the REST layer. If enabled, only HTTPS is allowed.
/// Type: boolean
pub const CONFIG_OPTION_PLUGINS_SECURITY_SSL_HTTP_ENABLED: &str =
    "plugins.security.ssl.http.enabled";

/// Path to the cert PEM file used for TLS on the HTTP PORT.
/// type: string
pub const CONFIG_OPTION_PLUGINS_SECURITY_SSL_HTTP_PEMCERT_FILEPATH: &str =
    "plugins.security.ssl.http.pemcert_filepath";

/// Path to the key PEM file used for TLS on the HTTP PORT.
/// type: string
pub const CONFIG_OPTION_PLUGINS_SECURITY_SSL_HTTP_PEMKEY_FILEPATH: &str =
    "plugins.security.ssl.http.pemkey_filepath";

/// Path to the trusted CAs PEM file used for TLS on the HTTP PORT.
/// type: string
pub const CONFIG_OPTION_PLUGINS_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH: &str =
    "plugins.security.ssl.http.pemtrustedcas_filepath";

/// Whether to enable TLS on internal node-to-node communication using the transport port.
/// type: boolean
pub const CONFIG_OPTION_PLUGINS_SECURITY_SSL_TRANSPORT_ENABLED: &str =
    "plugins.security.ssl.transport.enabled";

/// Path to the cert PEM file used for TLS on the transport PORT.
/// type: string
pub const CONFIG_OPTION_PLUGINS_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH: &str =
    "plugins.security.ssl.transport.pemcert_filepath";

/// Path to the key PEM file used for TLS on the transport PORT.
/// type: string
pub const CONFIG_OPTION_PLUGINS_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH: &str =
    "plugins.security.ssl.transport.pemkey_filepath";

/// Path to the trusted CAs PEM file used for TLS on the transport PORT.
/// type: string
pub const CONFIG_OPTION_PLUGINS_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH: &str =
    "plugins.security.ssl.transport.pemtrustedcas_filepath";

const DEFAULT_OPENSEARCH_HOME: &str = "/stackable/opensearch";

/// Configuration of an OpenSearch node based on the cluster and role-group configuration
pub struct NodeConfig {
    cluster: ValidatedCluster,
    role_group_name: RoleGroupName,
    role_group_config: OpenSearchRoleGroupConfig,
    pub discovery_service_name: ServiceName,
}

// Most functions are public because their configuration values could also be used in environment
// variables.
impl NodeConfig {
    pub fn new(
        cluster: ValidatedCluster,
        role_group_name: RoleGroupName,
        role_group_config: OpenSearchRoleGroupConfig,
        discovery_service_name: ServiceName,
    ) -> Self {
        Self {
            cluster,
            role_group_name,
            role_group_config,
            discovery_service_name,
        }
    }

    /// Creates the main OpenSearch configuration file in YAML format
    pub fn opensearch_config_file_content(&self) -> String {
        Self::to_yaml(self.opensearch_config())
    }

    pub fn opensearch_config(&self) -> serde_json::Map<String, Value> {
        let mut config = self.static_opensearch_config();

        config.append(&mut self.tls_config());

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

        config
    }

    /// Creates the main OpenSearch configuration file as JSON map
    ///
    /// The file should only contain cluster-wide configuration options. Node-specific options
    /// should be defined as environment variables.
    pub fn static_opensearch_config(&self) -> serde_json::Map<String, Value> {
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
        config.insert(
            CONFIG_OPTION_NODE_ATTR_ROLE_GROUP.to_owned(),
            json!(self.role_group_name),
        );

        config
    }

    pub fn tls_config(&self) -> serde_json::Map<String, Value> {
        let mut config = serde_json::Map::new();
        let opensearch_path_conf = self.opensearch_path_conf();

        // TLS config for TRANSPORT port which is always enabled.
        config.insert(
            CONFIG_OPTION_PLUGINS_SECURITY_SSL_TRANSPORT_ENABLED.to_owned(),
            json!(true),
        );
        config.insert(
            CONFIG_OPTION_PLUGINS_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH.to_owned(),
            json!(format!("{opensearch_path_conf}/tls/internal/tls.crt")),
        );
        config.insert(
            CONFIG_OPTION_PLUGINS_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH.to_owned(),
            json!(format!("{opensearch_path_conf}/tls/internal/tls.key")),
        );
        config.insert(
            CONFIG_OPTION_PLUGINS_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH.to_owned(),
            json!(format!("{opensearch_path_conf}/tls/internal/ca.crt")),
        );

        // TLS config for HTTP port (REST API) (optional).
        if self.cluster.tls_config.server_secret_class.is_some() {
            config.insert(
                CONFIG_OPTION_PLUGINS_SECURITY_SSL_HTTP_ENABLED.to_owned(),
                json!(true),
            );
            config.insert(
                CONFIG_OPTION_PLUGINS_SECURITY_SSL_HTTP_PEMCERT_FILEPATH.to_owned(),
                json!(format!("{opensearch_path_conf}/tls/server/tls.crt")),
            );
            config.insert(
                CONFIG_OPTION_PLUGINS_SECURITY_SSL_HTTP_PEMKEY_FILEPATH.to_owned(),
                json!(format!("{opensearch_path_conf}/tls/server/tls.key")),
            );
            config.insert(
                CONFIG_OPTION_PLUGINS_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH.to_owned(),
                json!(format!("{opensearch_path_conf}/tls/server/ca.crt")),
            );
        } else {
            config.insert(
                CONFIG_OPTION_PLUGINS_SECURITY_SSL_HTTP_ENABLED.to_owned(),
                json!(false),
            );
        }

        config
    }

    /// Returns `true` if TLS is enabled on the HTTP port
    pub fn tls_on_http_port_enabled(&self) -> bool {
        self.opensearch_config()
            .get(CONFIG_OPTION_PLUGINS_SECURITY_SSL_HTTP_ENABLED)
            .and_then(Self::value_as_bool)
            == Some(true)
    }

    /// Converts the given JSON value to [`bool`] if possible
    pub fn value_as_bool(value: &Value) -> Option<bool> {
        value.as_bool().or(
            // OpenSearch parses the strings "true" and "false" as boolean, see
            // https://github.com/opensearch-project/OpenSearch/blob/3.1.0/libs/common/src/main/java/org/opensearch/common/Booleans.java#L45-L84
            value
                .as_str()
                .and_then(|value| FromStr::from_str(value).ok()),
        )
    }

    /// Creates environment variables for the OpenSearch configurations
    ///
    /// The environment variables should only contain node-specific configuration options.
    /// Cluster-wide options should be added to the configuration file.
    pub fn environment_variables(&self) -> EnvVarSet {
        EnvVarSet::new()
            // Set the OpenSearch node name to the Pod name.
            // The node name is used e.g. for INITIAL_CLUSTER_MANAGER_NODES.
            .with_field_path(
                &EnvVarName::from_str_unsafe(CONFIG_OPTION_NODE_NAME),
                FieldPathEnvVar::Name,
            )
            .with_value(
                &EnvVarName::from_str_unsafe(CONFIG_OPTION_DISCOVERY_SEED_HOSTS),
                &self.discovery_service_name,
            )
            .with_value(
                &EnvVarName::from_str_unsafe(CONFIG_OPTION_INITIAL_CLUSTER_MANAGER_NODES),
                self.initial_cluster_manager_nodes(),
            )
            .with_value(
                &EnvVarName::from_str_unsafe(CONFIG_OPTION_NODE_ROLES),
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
            .merge(self.role_group_config.env_overrides.clone())
    }

    fn to_yaml(kv: serde_json::Map<String, Value>) -> String {
        kv.iter()
            .map(|(key, value)| format!("{key}: {value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Configuration for `discovery.type`
    ///
    /// "zen" is the default if `discovery.type` is not set.
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

            // This setting requires node names as set in NODE_NAME.
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

    /// Return content of the `OPENSEARCH_HOME` environment variable from envOverrides or default to `DEFAULT_OPENSEARCH_HOME`
    pub fn opensearch_home(&self) -> String {
        self.environment_variables()
            .get(&EnvVarName::from_str_unsafe("OPENSEARCH_HOME"))
            .and_then(|env_var| env_var.value.clone())
            .unwrap_or(DEFAULT_OPENSEARCH_HOME.to_owned())
    }

    /// Return content of the `OPENSEARCH_PATH_CONF` environment variable from envOverrides or default to `OPENSEARCH_HOME/config`
    pub fn opensearch_path_conf(&self) -> String {
        let opensearch_home = self.opensearch_home();
        self.environment_variables()
            .get(&EnvVarName::from_str_unsafe("OPENSEARCH_PATH_CONF"))
            .and_then(|env_var| env_var.value.clone())
            .unwrap_or(format!("{opensearch_home}/config"))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use stackable_operator::{
        commons::{
            affinity::StackableAffinity,
            product_image_selection::{ProductImage, ResolvedProductImage},
            resources::Resources,
        },
        k8s_openapi::api::core::v1::PodTemplateSpec,
        kvp::LabelValue,
        product_logging::spec::AutomaticContainerLogConfig,
        role_utils::GenericRoleConfig,
        shared::time::Duration,
    };
    use uuid::uuid;

    use super::*;
    use crate::{
        controller::{ValidatedLogging, ValidatedOpenSearchConfig},
        crd::{NodeRoles, v1alpha1},
        framework::{
            product_logging::framework::ValidatedContainerLogConfigChoice,
            role_utils::GenericProductSpecificCommonConfig,
            types::{
                kubernetes::{ListenerClassName, NamespaceName},
                operator::{ClusterName, ProductVersion, RoleGroupName},
            },
        },
    };

    struct TestConfig {
        replicas: u16,
        config_settings: &'static [(&'static str, &'static str)],
        env_vars: &'static [(&'static str, &'static str)],
    }

    impl Default for TestConfig {
        fn default() -> Self {
            Self {
                replicas: 3,
                config_settings: &[],
                env_vars: &[],
            }
        }
    }

    fn node_config(test_config: TestConfig) -> NodeConfig {
        let image: ProductImage = serde_json::from_str(r#"{"productVersion": "3.1.0"}"#)
            .expect("should be a valid ProductImage");

        let role_group_name = RoleGroupName::from_str_unsafe("data");

        let role_group_config = OpenSearchRoleGroupConfig {
            replicas: test_config.replicas,
            config: ValidatedOpenSearchConfig {
                affinity: StackableAffinity::default(),
                listener_class: ListenerClassName::from_str_unsafe("cluster-internal"),
                logging: ValidatedLogging {
                    opensearch_container: ValidatedContainerLogConfigChoice::Automatic(
                        AutomaticContainerLogConfig::default(),
                    ),
                    vector_container: None,
                },
                node_roles: NodeRoles(vec![
                    v1alpha1::NodeRole::ClusterManager,
                    v1alpha1::NodeRole::Data,
                    v1alpha1::NodeRole::Ingest,
                    v1alpha1::NodeRole::RemoteClusterClient,
                ]),
                requested_secret_lifetime: Duration::from_str("1d")
                    .expect("should be a valid duration"),
                resources: Resources::default(),
                termination_grace_period_seconds: 30,
            },
            config_overrides: [(
                CONFIGURATION_FILE_OPENSEARCH_YML.to_owned(),
                test_config
                    .config_settings
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )]
            .into(),
            env_overrides: EnvVarSet::new().with_values(
                test_config
                    .env_vars
                    .iter()
                    .map(|(k, v)| (EnvVarName::from_str_unsafe(k), *v)),
            ),
            cli_overrides: BTreeMap::default(),
            pod_overrides: PodTemplateSpec::default(),
            product_specific_common_config: GenericProductSpecificCommonConfig::default(),
        };

        let cluster = ValidatedCluster::new(
            ResolvedProductImage {
                product_version: "3.1.0".to_owned(),
                app_version_label_value: LabelValue::from_str("3.1.0-stackable0.0.0-dev")
                    .expect("should be a valid label value"),
                image: "oci.stackable.tech/sdp/opensearch:3.1.0-stackable0.0.0-dev".to_string(),
                image_pull_policy: "Always".to_owned(),
                pull_secrets: None,
            },
            ProductVersion::from_str_unsafe(image.product_version()),
            ClusterName::from_str_unsafe("my-opensearch-cluster"),
            NamespaceName::from_str_unsafe("default"),
            uuid!("0b1e30e6-326e-4c1a-868d-ad6598b49e8b"),
            GenericRoleConfig::default(),
            [(
                RoleGroupName::from_str_unsafe("default"),
                role_group_config.clone(),
            )]
            .into(),
            v1alpha1::OpenSearchTls::default(),
        );

        NodeConfig::new(
            cluster,
            role_group_name,
            role_group_config,
            ServiceName::from_str_unsafe("my-opensearch-cluster-manager"),
        )
    }

    #[test]
    pub fn test_static_opensearch_config_file() {
        let node_config = node_config(TestConfig {
            config_settings: &[("test", "value")],
            ..TestConfig::default()
        });

        assert_eq!(
            concat!(
                "cluster.name: \"my-opensearch-cluster\"\n",
                "discovery.type: \"zen\"\n",
                "network.host: \"0.0.0.0\"\n",
                "node.attr.role-group: \"data\"\n",
                "plugins.security.nodes_dn: [\"CN=generated certificate for pod\"]\n",
                "plugins.security.ssl.http.enabled: true\n",
                "plugins.security.ssl.http.pemcert_filepath: \"/stackable/opensearch/config/tls/server/tls.crt\"\n",
                "plugins.security.ssl.http.pemkey_filepath: \"/stackable/opensearch/config/tls/server/tls.key\"\n",
                "plugins.security.ssl.http.pemtrustedcas_filepath: \"/stackable/opensearch/config/tls/server/ca.crt\"\n",
                "plugins.security.ssl.transport.enabled: true\n",
                "plugins.security.ssl.transport.pemcert_filepath: \"/stackable/opensearch/config/tls/internal/tls.crt\"\n",
                "plugins.security.ssl.transport.pemkey_filepath: \"/stackable/opensearch/config/tls/internal/tls.key\"\n",
                "plugins.security.ssl.transport.pemtrustedcas_filepath: \"/stackable/opensearch/config/tls/internal/ca.crt\"\n",
                "test: \"value\"",
            )
            .to_owned(),
            node_config.opensearch_config_file_content()
        );
    }

    #[test]
    pub fn test_tls_on_http_port_enabled() {
        let node_config_tls_undefined = node_config(TestConfig::default());

        let node_config_tls_enabled = node_config(TestConfig {
            config_settings: &[("plugins.security.ssl.http.enabled", "true")],
            ..TestConfig::default()
        });

        let node_config_tls_disabled = node_config(TestConfig {
            config_settings: &[("plugins.security.ssl.http.enabled", "false")],
            ..TestConfig::default()
        });

        assert!(node_config_tls_undefined.tls_on_http_port_enabled());
        assert!(node_config_tls_enabled.tls_on_http_port_enabled());
        assert!(!node_config_tls_disabled.tls_on_http_port_enabled());
    }

    #[test]
    pub fn test_value_as_bool() {
        // boolean
        assert_eq!(Some(true), NodeConfig::value_as_bool(&Value::Bool(true)));
        assert_eq!(Some(false), NodeConfig::value_as_bool(&Value::Bool(false)));

        // valid strings
        assert_eq!(
            Some(true),
            NodeConfig::value_as_bool(&Value::String("true".to_owned()))
        );
        assert_eq!(
            Some(false),
            NodeConfig::value_as_bool(&Value::String("false".to_owned()))
        );

        // invalid strings
        assert_eq!(
            None,
            NodeConfig::value_as_bool(&Value::String("True".to_owned()))
        );

        // invalid types
        assert_eq!(None, NodeConfig::value_as_bool(&Value::Null));
        assert_eq!(
            None,
            NodeConfig::value_as_bool(&Value::Number(
                serde_json::Number::from_i128(1).expect("should be a valid number")
            ))
        );
        assert_eq!(None, NodeConfig::value_as_bool(&Value::Array(vec![])));
        assert_eq!(
            None,
            NodeConfig::value_as_bool(&Value::Object(serde_json::Map::new()))
        );
    }

    #[test]
    pub fn test_environment_variables() {
        let node_config = node_config(TestConfig {
            replicas: 2,
            env_vars: &[("TEST", "value")],
            ..TestConfig::default()
        });

        assert_eq!(
            EnvVarSet::new()
                .with_value(&EnvVarName::from_str_unsafe("TEST"), "value")
                .with_value(
                    &EnvVarName::from_str_unsafe("cluster.initial_cluster_manager_nodes"),
                    "my-opensearch-cluster-nodes-default-0,my-opensearch-cluster-nodes-default-1",
                )
                .with_value(
                    &EnvVarName::from_str_unsafe("discovery.seed_hosts"),
                    "my-opensearch-cluster-manager",
                )
                .with_field_path(
                    &EnvVarName::from_str_unsafe("node.name"),
                    FieldPathEnvVar::Name
                )
                .with_value(
                    &EnvVarName::from_str_unsafe("node.roles"),
                    "cluster_manager,data,ingest,remote_cluster_client"
                ),
            node_config.environment_variables()
        );
    }

    #[test]
    pub fn test_discovery_type() {
        let node_config_single_node = node_config(TestConfig {
            replicas: 1,
            ..TestConfig::default()
        });

        let node_config_multiple_nodes = node_config(TestConfig {
            replicas: 2,
            ..TestConfig::default()
        });

        assert_eq!(
            "single-node".to_owned(),
            node_config_single_node.discovery_type()
        );
        assert_eq!(
            "zen".to_owned(),
            node_config_multiple_nodes.discovery_type()
        );
    }

    #[test]
    pub fn test_initial_cluster_manager_nodes() {
        let node_config_single_node = node_config(TestConfig {
            replicas: 1,
            ..TestConfig::default()
        });

        let node_config_multiple_nodes = node_config(TestConfig {
            replicas: 3,
            ..TestConfig::default()
        });

        assert_eq!(
            "".to_owned(),
            node_config_single_node.initial_cluster_manager_nodes()
        );
        assert_eq!(
            "my-opensearch-cluster-nodes-default-0,my-opensearch-cluster-nodes-default-1,my-opensearch-cluster-nodes-default-2".to_owned(),
            node_config_multiple_nodes.initial_cluster_manager_nodes()
        );
    }
}
