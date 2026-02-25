use std::{array, slice, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::json;
use stackable_operator::{
    commons::{
        affinity::{StackableAffinity, StackableAffinityFragment, affinity_between_role_pods},
        cluster_operation::ClusterOperation,
        product_image_selection::ProductImage,
        resources::{
            CpuLimitsFragment, MemoryLimitsFragment, NoRuntimeLimitsFragment, PvcConfig,
            PvcConfigFragment, Resources, ResourcesFragment,
        },
    },
    config::{
        fragment::Fragment,
        merge::{Atomic, Merge},
    },
    deep_merger::ObjectOverrides,
    k8s_openapi::{api::core::v1::PodAntiAffinity, apimachinery::pkg::api::resource::Quantity},
    kube::CustomResource,
    product_logging::{self, spec::Logging},
    role_utils::{GenericRoleConfig, Role},
    schemars::{self, JsonSchema},
    shared::time::Duration,
    status::condition::{ClusterCondition, HasStatusCondition},
    utils::crds::raw_object_schema,
    versioned::versioned,
};
use strum::{Display, EnumIter};

use crate::{
    attributed_string_type, constant,
    framework::{
        NameIsValidLabelValue,
        role_utils::GenericProductSpecificCommonConfig,
        types::{
            kubernetes::{
                ConfigMapKey, ConfigMapName, ContainerName, ListenerClassName, SecretClassName,
                SecretKey, SecretName,
            },
            operator::{ClusterName, ProductName, RoleGroupName, RoleName},
        },
    },
};

constant!(DEFAULT_ROLE_GROUP_LISTENER_CLASS: ListenerClassName = "cluster-internal");
constant!(DEFAULT_DISCOVERY_SERVICE_LISTENER_CLASS: ListenerClassName = "cluster-internal");
constant!(TLS_DEFAULT_SECRET_CLASS: SecretClassName = "tls");

#[versioned(
    version(name = "v1alpha1"),
    crates(
        k8s_openapi = "stackable_operator::k8s_openapi",
        kube_client = "stackable_operator::kube::client",
        kube_core = "stackable_operator::kube::core",
        schemars = "stackable_operator::schemars",
        versioned = "stackable_operator::versioned"
    )
)]
pub mod versioned {

    /// An OpenSearch cluster stacklet. This resource is managed by the Stackable operator for
    /// OpenSearch. Find more information on how to use it and the resources that the operator
    /// generates in the [operator documentation](DOCS_BASE_URL_PLACEHOLDER/opensearch/).
    #[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[versioned(crd(
        group = "opensearch.stackable.tech",
        kind = "OpenSearchCluster",
        plural = "opensearchclusters",
        shortname = "opensearch",
        status = "v1alpha1::OpenSearchClusterStatus",
        namespaced
    ))]
    #[serde(rename_all = "camelCase")]
    pub struct OpenSearchClusterSpec {
        // no doc - docs in ProductImage struct
        pub image: ProductImage,

        /// Configuration that applies to all roles and role groups
        #[serde(default)]
        pub cluster_config: v1alpha1::OpenSearchClusterConfig,

        // no doc - docs in ClusterOperation struct
        #[serde(default)]
        pub cluster_operation: ClusterOperation,

        // no doc - docs in ObjectOverrides struct
        #[serde(default)]
        pub object_overrides: ObjectOverrides,

        // no doc - docs in Role struct
        pub nodes: Role<
            OpenSearchConfigFragment,
            OpenSearchRoleConfig,
            GenericProductSpecificCommonConfig,
        >,
    }

    #[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct OpenSearchClusterConfig {
        /// Entries to add to the OpenSearch keystore.
        #[serde(default)]
        pub keystore: Vec<OpenSearchKeystore>,

        /// Configuration of the OpenSearch security plugin
        #[serde(default)]
        pub security: Security,

        /// TLS configuration options for the server (REST API) and internal communication (transport).
        ///
        /// This configuration is only effective if the OpenSearch security plugin is not disabled.
        #[serde(default)]
        pub tls: OpenSearchTls,

        /// Name of the Vector aggregator [discovery ConfigMap](DOCS_BASE_URL_PLACEHOLDER/concepts/service_discovery).
        /// It must contain the key `ADDRESS` with the address of the Vector aggregator.
        /// Follow the [logging tutorial](DOCS_BASE_URL_PLACEHOLDER/tutorials/logging-vector-aggregator)
        /// to learn how to configure log aggregation with Vector.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub vector_aggregator_config_map_name: Option<ConfigMapName>,
    }

    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct OpenSearchKeystore {
        /// Key in the OpenSearch keystore
        pub key: OpenSearchKeystoreKey,

        /// Reference to the Secret containing the value which will be stored in the OpenSearch keystore
        pub secret_key_ref: SecretKeyRef,
    }

    /// Configuration of the OpenSearch security plugin
    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Security {
        /// Whether to enable the OpenSearch security plugin
        ///
        /// Disabling the security plugin also disables TLS and exposes the security index if it
        /// exists.
        #[serde(default = "security_config_enabled_default")]
        pub enabled: bool,

        /// The role group that updates the security index if any setting is managed by the operator.
        #[serde(default = "security_config_managing_role_group")]
        pub managing_role_group: RoleGroupName,

        /// Settings for the OpenSearch security plugin
        #[serde(default)]
        pub settings: SecuritySettings,
    }

    /// Configuration files of the OpenSearch security plugin
    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SecuritySettings {
        /// User-defined action groups
        ///
        /// see <https://docs.opensearch.org/latest/security/configuration/yaml/#action_groupsyml>
        #[serde(default = "security_settings_file_type_default_actiongroups")]
        pub action_groups: SecuritySettingsFileType,

        /// List of allowed HTTP endpoints
        ///
        /// see <https://docs.opensearch.org/latest/security/configuration/yaml/#allowlistyml>
        #[serde(default = "security_settings_file_type_default_allowlist")]
        pub allow_list: SecuritySettingsFileType,

        /// Settings for audit logging
        ///
        /// see
        /// <https://docs.opensearch.org/latest/security/audit-logs/index/#settings-in-audityml>
        #[serde(default = "security_settings_file_type_default_audit")]
        pub audit: SecuritySettingsFileType,

        /// Configuration of the security backend
        ///
        /// see <https://docs.opensearch.org/latest/security/configuration/configuration/>
        #[serde(default = "security_settings_file_type_default_config")]
        pub config: SecuritySettingsFileType,

        /// The internal user database
        ///
        /// see <https://docs.opensearch.org/latest/security/configuration/yaml/#internal_usersyml>
        #[serde(default = "security_settings_file_type_default_internalusers")]
        pub internal_users: SecuritySettingsFileType,

        /// Distinguished names (DNs) of nodes to allow communication between nodes and clusters
        ///
        /// see <https://docs.opensearch.org/latest/security/configuration/yaml/#nodes_dnyml>
        #[serde(default = "security_settings_file_type_default_nodesdn")]
        pub nodes_dn: SecuritySettingsFileType,

        /// Definition of roles in the security plugin
        ///
        /// see <https://docs.opensearch.org/latest/security/configuration/yaml/#rolesyml>
        #[serde(default = "security_settings_file_type_default_roles")]
        pub roles: SecuritySettingsFileType,

        /// Role mappings to users or backend roles
        ///
        /// see <https://docs.opensearch.org/latest/security/configuration/yaml/#roles_mappingyml>
        #[serde(default = "security_settings_file_type_default_rolesmapping")]
        pub roles_mapping: SecuritySettingsFileType,

        /// OpenSearch Dashboards tenants
        ///
        /// see <https://docs.opensearch.org/latest/security/configuration/yaml/#tenantsyml>
        #[serde(default = "security_settings_file_type_default_tenants")]
        pub tenants: SecuritySettingsFileType,
    }

    /// Specific configuration file of the OpenSearch security plugin
    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SecuritySettingsFileType {
        /// Whether this configuration should only be applied initially and afterwards be managed
        /// via the "API", or managed all the time by the "operator".
        ///
        /// If this configuration is changed later from "API" to "operator", then the changes made
        /// via the API are overridden.
        // There is no default, so that the user is aware of this choice.
        pub managed_by: SecuritySettingsFileTypeManagedBy,

        /// The content of the security configuration file
        pub content: SecuritySettingsFileTypeContent,
    }

    /// Responsibility for initializing and updating the security configuration
    #[derive(
        Clone,
        Debug,
        Deserialize,
        Display,
        EnumIter,
        Eq,
        JsonSchema,
        Ord,
        PartialEq,
        PartialOrd,
        Serialize,
    )]
    pub enum SecuritySettingsFileTypeManagedBy {
        /// Only initially applied by the operator, but afterwards managed via the API.
        #[serde(rename = "API")]
        Api,

        /// Managed by the operator; Changes made via the API will be eventually overridden.
        #[serde(rename = "operator")]
        Operator,
    }

    /// Content of the security configuration file
    #[derive(Clone, Debug, Deserialize, Display, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub enum SecuritySettingsFileTypeContent {
        /// Security configuration file content defined inline
        Value(SecuritySettingsFileTypeContentValue),

        /// Security configuration file content ingested from a ConfigMap or Secret
        ValueFrom(SecuritySettingsFileTypeContentValueFrom),
    }

    /// Security configuration file content defined inline
    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    pub struct SecuritySettingsFileTypeContentValue {
        #[serde(flatten)]
        #[schemars(schema_with = "raw_object_schema")]
        value: serde_json::Value,
    }

    /// Security configuration file content ingested from a ConfigMap or Secret
    #[derive(Clone, Debug, Deserialize, Display, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub enum SecuritySettingsFileTypeContentValueFrom {
        /// Reference to a key in a ConfigMap
        ConfigMapKeyRef(ConfigMapKeyRef),

        /// Reference to a key in a Secret
        SecretKeyRef(SecretKeyRef),
    }

    /// Reference to a key in a ConfigMap
    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    pub struct ConfigMapKeyRef {
        /// Name of the ConfigMap
        pub name: ConfigMapName,

        /// Key in the ConfigMap that contains the value
        pub key: ConfigMapKey,
    }

    /// Reference to a key in a Secret
    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    pub struct SecretKeyRef {
        /// Name of the Secret
        pub name: SecretName,

        /// Key in the Secret that contains the value
        pub key: SecretKey,
    }

    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct OpenSearchTls {
        /// Only affects client connections to the REST API.
        /// This setting controls:
        /// - If TLS encryption is used at all
        /// - Which cert the servers should use to authenticate themselves against the client
        #[serde(
            default = "server_secret_class_default",
            skip_serializing_if = "Option::is_none"
        )]
        pub server_secret_class: Option<SecretClassName>,

        /// Only affects internal communication (transport). Used for mutual verification between OpenSearch nodes.
        /// This setting controls:
        /// - Which cert the servers should use to authenticate themselves against other servers
        /// - Which ca.crt to use when validating the other server
        #[serde(default = "internal_secret_class_default")]
        pub internal_secret_class: SecretClassName,
    }

    // The possible node roles are by default the built-in roles and the search role, see
    // https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/node/DiscoveryNode.java#L609-L614.
    //
    // Plugins can set additional roles, see
    // https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/node/DiscoveryNode.java#L629-L646.
    //
    // For instance, the ml-commons plugin adds the node role "ml", see
    // https://github.com/opensearch-project/ml-commons/blob/3.0.0.0/plugin/src/main/java/org/opensearch/ml/plugin/MachineLearningPlugin.java#L394.
    // If such a plugin is added, then this enumeration must be extended accordingly.
    #[derive(
        Clone,
        Debug,
        Deserialize,
        Display,
        EnumIter,
        Eq,
        JsonSchema,
        Ord,
        PartialEq,
        PartialOrd,
        Serialize,
    )]
    // The OpenSearch configuration uses snake_case. To make it easier to match the log output of
    // OpenSearch with this cluster configuration, snake_case is also used here.
    #[serde(rename_all = "snake_case")]
    #[strum(serialize_all = "snake_case")]
    pub enum NodeRole {
        // Built-in node roles
        // see https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/node/DiscoveryNodeRole.java#L341-L346
        ClusterManager,
        CoordinatingOnly,
        Data,
        Ingest,
        RemoteClusterClient,
        Warm,

        // Search node role
        // see https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/node/DiscoveryNodeRole.java#L313-L339
        Search,
    }

    #[derive(Clone, Debug, Fragment, JsonSchema, PartialEq)]
    #[fragment_attrs(
        derive(
            Clone,
            Debug,
            Default,
            Deserialize,
            Merge,
            JsonSchema,
            PartialEq,
            Serialize
        ),
        serde(rename_all = "camelCase")
    )]
    pub struct OpenSearchConfig {
        #[fragment_attrs(serde(default))]
        pub affinity: StackableAffinity,

        /// Determines whether this role group is exposed in the discovery service.
        pub discovery_service_exposed: bool,

        /// Time period Pods have to gracefully shut down, e.g. `30m`, `1h` or `2d`. Consult the
        /// operator documentation for details.
        #[fragment_attrs(serde(default))]
        pub graceful_shutdown_timeout: Duration,

        /// This field controls which
        /// [ListenerClass](https://docs.stackable.tech/home/nightly/listener-operator/listenerclass.html)
        /// is used to expose the HTTP communication.
        #[fragment_attrs(serde(default))]
        pub listener_class: ListenerClassName,

        // no doc - docs in Logging struct
        #[fragment_attrs(serde(default))]
        pub logging: Logging<Container>,

        /// Roles of the OpenSearch node.
        ///
        /// Consult the [node roles
        /// documentation](DOCS_BASE_URL_PLACEHOLDER/opensearch/usage-guide/node-roles) for details.
        pub node_roles: NodeRoles,

        /// Request secret (currently only autoTls certificates) lifetime from the secret operator, e.g. `7d`, or `30d`.
        /// This can be shortened by the `maxCertificateLifetime` setting on the SecretClass issuing the TLS certificate.
        ///
        /// Defaults to 1d.
        #[fragment_attrs(serde(default))]
        pub requested_secret_lifetime: Duration,

        #[fragment_attrs(serde(default))]
        pub resources: Resources<StorageConfig>,
    }

    #[derive(
        Clone,
        Debug,
        Deserialize,
        Display,
        Eq,
        EnumIter,
        JsonSchema,
        Ord,
        PartialEq,
        PartialOrd,
        Serialize,
    )]
    pub enum Container {
        #[serde(rename = "opensearch")]
        OpenSearch,

        #[serde(rename = "vector")]
        Vector,

        #[serde(rename = "create-admin-certificate")]
        CreateAdminCertificate,

        #[serde(rename = "update-security-config")]
        UpdateSecurityConfig,

        #[serde(rename = "init-keystore")]
        InitKeystore,
    }

    #[derive(Clone, Debug, Default, JsonSchema, PartialEq, Fragment)]
    #[fragment_attrs(
        derive(
            Clone,
            Debug,
            Default,
            Deserialize,
            Merge,
            JsonSchema,
            PartialEq,
            Serialize
        ),
        serde(rename_all = "camelCase")
    )]
    pub struct StorageConfig {
        #[fragment_attrs(serde(default))]
        pub data: PvcConfig,
    }

    #[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct OpenSearchRoleConfig {
        #[serde(flatten)]
        pub common: GenericRoleConfig,

        /// The [ListenerClass](https://docs.stackable.tech/home/nightly/listener-operator/listenerclass.html) that is used for the discovery service.
        #[serde(default = "discovery_service_listener_class_default")]
        pub discovery_service_listener_class: ListenerClassName,
    }

    #[derive(Clone, Default, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct OpenSearchClusterStatus {
        /// An opaque value that changes every time a discovery detail does
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub discovery_hash: Option<String>,
        #[serde(default)]
        pub conditions: Vec<ClusterCondition>,
    }
}

impl HasStatusCondition for v1alpha1::OpenSearchCluster {
    fn conditions(&self) -> Vec<ClusterCondition> {
        match &self.status {
            Some(status) => status.conditions.clone(),
            None => vec![],
        }
    }
}

impl v1alpha1::OpenSearchConfig {
    pub fn default_config(
        product_name: &ProductName,
        cluster_name: &ClusterName,
        role_name: &RoleName,
    ) -> v1alpha1::OpenSearchConfigFragment {
        v1alpha1::OpenSearchConfigFragment {
            affinity: StackableAffinityFragment {
                pod_affinity: None,
                pod_anti_affinity: Some(PodAntiAffinity {
                    preferred_during_scheduling_ignored_during_execution: Some(vec![
                        affinity_between_role_pods(
                            &product_name.to_label_value(),
                            &cluster_name.to_label_value(),
                            &role_name.to_label_value(),
                            1,
                        ),
                    ]),
                    required_during_scheduling_ignored_during_execution: None,
                }),
                node_affinity: None,
                node_selector: None,
            },
            discovery_service_exposed: Some(true),
            // Default taken from the Helm chart, see
            // https://github.com/opensearch-project/helm-charts/blob/opensearch-3.0.0/charts/opensearch/values.yaml#L364
            graceful_shutdown_timeout: Some(
                Duration::from_str("2m").expect("should be a valid duration"),
            ),
            listener_class: Some(DEFAULT_ROLE_GROUP_LISTENER_CLASS.to_owned()),
            logging: product_logging::spec::default_logging(),
            // Defaults taken from the Helm chart, see
            // https://github.com/opensearch-project/helm-charts/blob/opensearch-3.0.0/charts/opensearch/values.yaml#L16-L20
            node_roles: Some(NodeRoles(vec![
                v1alpha1::NodeRole::ClusterManager,
                v1alpha1::NodeRole::Ingest,
                v1alpha1::NodeRole::Data,
                v1alpha1::NodeRole::RemoteClusterClient,
            ])),
            requested_secret_lifetime: Some(
                Duration::from_str("1d").expect("should be a valid duration"),
            ),
            resources: ResourcesFragment {
                memory: MemoryLimitsFragment {
                    // An idle node already requires 2 Gi.
                    limit: Some(Quantity("2Gi".to_owned())),
                    runtime_limits: NoRuntimeLimitsFragment {},
                },
                cpu: CpuLimitsFragment {
                    // Default taken from the Helm chart, see
                    // https://github.com/opensearch-project/helm-charts/blob/opensearch-3.0.0/charts/opensearch/values.yaml#L150
                    min: Some(Quantity("1".to_owned())),
                    // an arbitrary value
                    max: Some(Quantity("4".to_owned())),
                },
                storage: v1alpha1::StorageConfigFragment {
                    data: PvcConfigFragment {
                        // Default taken from the Helm chart, see
                        // https://github.com/opensearch-project/helm-charts/blob/opensearch-3.0.0/charts/opensearch/values.yaml#L220
                        // This value should be overriden by the user. Data nodes need probably
                        // more, the other nodes less.
                        capacity: Some(Quantity("8Gi".to_owned())),
                        storage_class: None,
                        selectors: None,
                    },
                },
            },
        }
    }
}

impl Default for v1alpha1::Security {
    fn default() -> Self {
        Self {
            enabled: security_config_enabled_default(),
            managing_role_group: security_config_managing_role_group(),
            settings: v1alpha1::SecuritySettings::default(),
        }
    }
}

impl v1alpha1::SecuritySettings {
    pub fn is_only_managed_by_api(&self) -> bool {
        self.into_iter()
            .all(|config| *config.managed_by == v1alpha1::SecuritySettingsFileTypeManagedBy::Api)
    }
}

impl Default for v1alpha1::SecuritySettings {
    fn default() -> Self {
        Self {
            action_groups: security_settings_file_type_default_actiongroups(),
            allow_list: security_settings_file_type_default_allowlist(),
            audit: security_settings_file_type_default_audit(),
            config: security_settings_file_type_default_config(),
            internal_users: security_settings_file_type_default_internalusers(),
            nodes_dn: security_settings_file_type_default_nodesdn(),
            roles_mapping: security_settings_file_type_default_rolesmapping(),
            roles: security_settings_file_type_default_roles(),
            tenants: security_settings_file_type_default_tenants(),
        }
    }
}

/// [`v1alpha1::SecuritySettingsFileType`] extended with ID and filename
pub struct ExtendedSecuritySettingsFileType<'a> {
    /// The ID of the file type as set in the `_meta.type` field; can be used to construct
    /// volume names
    pub id: &'static str,

    /// The file name as expected by the OpenSearch security plugin
    pub filename: &'static str,

    pub managed_by: &'a v1alpha1::SecuritySettingsFileTypeManagedBy,

    pub content: &'a v1alpha1::SecuritySettingsFileTypeContent,
}

impl<'a> IntoIterator for &'a v1alpha1::SecuritySettings {
    type IntoIter = array::IntoIter<Self::Item, 9>;
    type Item = ExtendedSecuritySettingsFileType<'a>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIterator::into_iter([
            ExtendedSecuritySettingsFileType {
                id: "actiongroups",
                filename: "action_groups.yml",
                managed_by: &self.action_groups.managed_by,
                content: &self.action_groups.content,
            },
            ExtendedSecuritySettingsFileType {
                id: "allowlist",
                filename: "allow_list.yml",
                managed_by: &self.allow_list.managed_by,
                content: &self.allow_list.content,
            },
            ExtendedSecuritySettingsFileType {
                id: "audit",
                filename: "audit.yml",
                managed_by: &self.audit.managed_by,
                content: &self.audit.content,
            },
            ExtendedSecuritySettingsFileType {
                id: "config",
                filename: "config.yml",
                managed_by: &self.config.managed_by,
                content: &self.config.content,
            },
            ExtendedSecuritySettingsFileType {
                id: "internalusers",
                filename: "internal_users.yml",
                managed_by: &self.internal_users.managed_by,
                content: &self.internal_users.content,
            },
            ExtendedSecuritySettingsFileType {
                id: "nodesdn",
                filename: "nodes_dn.yml",
                managed_by: &self.nodes_dn.managed_by,
                content: &self.nodes_dn.content,
            },
            ExtendedSecuritySettingsFileType {
                id: "roles",
                filename: "roles.yml",
                managed_by: &self.roles.managed_by,
                content: &self.roles.content,
            },
            ExtendedSecuritySettingsFileType {
                id: "rolesmapping",
                filename: "roles_mapping.yml",
                managed_by: &self.roles_mapping.managed_by,
                content: &self.roles_mapping.content,
            },
            ExtendedSecuritySettingsFileType {
                id: "tenants",
                filename: "tenants.yml",
                managed_by: &self.tenants.managed_by,
                content: &self.tenants.content,
            },
        ])
    }
}

fn security_config_enabled_default() -> bool {
    true
}

fn security_config_managing_role_group() -> RoleGroupName {
    RoleGroupName::from_str("security-config").expect("should be a valid role group name")
}

fn security_settings_file_type_default_actiongroups() -> v1alpha1::SecuritySettingsFileType {
    security_settings_file_type_default(json!({
      "_meta": {
        "type": "actiongroups",
        "config_version": 2
      }
    }))
}

fn security_settings_file_type_default_allowlist() -> v1alpha1::SecuritySettingsFileType {
    security_settings_file_type_default(json!({
      "_meta": {
        "type": "allowlist",
        "config_version": 2
      },
      "config": {
        "enabled": false
      }
    }))
}

fn security_settings_file_type_default_audit() -> v1alpha1::SecuritySettingsFileType {
    security_settings_file_type_default(json!({
      "_meta": {
        "type": "audit",
        "config_version": 2
      },
      "config": {
        "enabled": false
      }
    }))
}

fn security_settings_file_type_default_config() -> v1alpha1::SecuritySettingsFileType {
    security_settings_file_type_default(json!({
      "_meta": {
        "type": "config",
        "config_version": 2
      },
      "config": {
        "dynamic": {
          "http": {},
          "authc": {},
          "authz": {}
        }
      }
    }))
}

fn security_settings_file_type_default_internalusers() -> v1alpha1::SecuritySettingsFileType {
    security_settings_file_type_default(json!({
      "_meta": {
        "type": "internalusers",
        "config_version": 2
      }
    }))
}

fn security_settings_file_type_default_nodesdn() -> v1alpha1::SecuritySettingsFileType {
    security_settings_file_type_default(json!({
      "_meta": {
        "type": "nodesdn",
        "config_version": 2
      }
    }))
}

fn security_settings_file_type_default_roles() -> v1alpha1::SecuritySettingsFileType {
    security_settings_file_type_default(json!({
      "_meta": {
        "type": "roles",
        "config_version": 2
      }
    }))
}

fn security_settings_file_type_default_rolesmapping() -> v1alpha1::SecuritySettingsFileType {
    security_settings_file_type_default(json!({
      "_meta": {
        "type": "rolesmapping",
        "config_version": 2
      }
    }))
}

fn security_settings_file_type_default_tenants() -> v1alpha1::SecuritySettingsFileType {
    security_settings_file_type_default(json!({
      "_meta": {
        "type": "tenants",
        "config_version": 2
      }
    }))
}

fn security_settings_file_type_default(
    value: serde_json::Value,
) -> v1alpha1::SecuritySettingsFileType {
    v1alpha1::SecuritySettingsFileType {
        managed_by: v1alpha1::SecuritySettingsFileTypeManagedBy::Api,
        content: v1alpha1::SecuritySettingsFileTypeContent::Value(
            v1alpha1::SecuritySettingsFileTypeContentValue { value },
        ),
    }
}

impl Default for v1alpha1::OpenSearchTls {
    fn default() -> Self {
        v1alpha1::OpenSearchTls {
            server_secret_class: server_secret_class_default(),
            internal_secret_class: internal_secret_class_default(),
        }
    }
}

fn server_secret_class_default() -> Option<SecretClassName> {
    Some(TLS_DEFAULT_SECRET_CLASS.to_owned())
}

fn internal_secret_class_default() -> SecretClassName {
    TLS_DEFAULT_SECRET_CLASS.to_owned()
}

impl Default for v1alpha1::OpenSearchRoleConfig {
    fn default() -> Self {
        v1alpha1::OpenSearchRoleConfig {
            common: GenericRoleConfig::default(),
            discovery_service_listener_class: discovery_service_listener_class_default(),
        }
    }
}

fn discovery_service_listener_class_default() -> ListenerClassName {
    DEFAULT_DISCOVERY_SERVICE_LISTENER_CLASS.to_owned()
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct NodeRoles(pub Vec<v1alpha1::NodeRole>);

impl NodeRoles {
    pub fn contains(&self, node_role: &v1alpha1::NodeRole) -> bool {
        self.0.contains(node_role)
    }

    pub fn iter(&self) -> slice::Iter<'_, v1alpha1::NodeRole> {
        self.0.iter()
    }
}

impl Atomic for NodeRoles {}

impl v1alpha1::Container {
    /// Returns the validated container name
    ///
    /// This name should match the one defined by the user (see the serde annotation at
    /// [`v1alpha1::Container`], but it could differ if it was renamed.
    pub fn to_container_name(&self) -> ContainerName {
        ContainerName::from_str(match self {
            v1alpha1::Container::OpenSearch => "opensearch",
            v1alpha1::Container::Vector => "vector",
            v1alpha1::Container::CreateAdminCertificate => "create-admin-certificate",
            v1alpha1::Container::UpdateSecurityConfig => "update-security-config",
            v1alpha1::Container::InitKeystore => "init-keystore",
        })
        .expect("should be a valid container name")
    }
}

// See https://github.com/opensearch-project/OpenSearch/blob/8ff7c6ee924a49f0f59f80a6e1c73073c8904214/server/src/main/java/org/opensearch/common/settings/KeyStoreWrapper.java#L125
attributed_string_type! {
    OpenSearchKeystoreKey,
    "Key in an OpenSearch keystore",
    "s3.client.default.access_key",
    (min_length = 1),
    (regex = "^[A-Za-z0-9_\\-.]+$")
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use crate::crd::v1alpha1;

    #[test]
    fn test_node_role() {
        assert_eq!(
            String::from("cluster_manager"),
            v1alpha1::NodeRole::ClusterManager.to_string()
        );
        assert_eq!(
            String::from("cluster_manager"),
            format!("{}", v1alpha1::NodeRole::ClusterManager)
        );
        assert_eq!(
            "\"cluster_manager\"",
            serde_json::to_string(&v1alpha1::NodeRole::ClusterManager)
                .expect("should be serializable")
        );
        assert_eq!(
            v1alpha1::NodeRole::ClusterManager,
            serde_json::from_str("\"cluster_manager\"").expect("should be deserializable")
        );
    }

    #[test]
    fn test_to_container_name() {
        for container in v1alpha1::Container::iter() {
            // Test that the function does not panic
            container.to_container_name();
        }
    }
}
