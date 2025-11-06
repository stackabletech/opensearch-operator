use std::{slice, str::FromStr};

use serde::{Deserialize, Serialize};
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
    k8s_openapi::{api::core::v1::PodAntiAffinity, apimachinery::pkg::api::resource::Quantity},
    kube::CustomResource,
    product_logging::{self, spec::Logging},
    role_utils::{GenericRoleConfig, Role},
    schemars::{self, JsonSchema},
    shared::time::Duration,
    status::condition::{ClusterCondition, HasStatusCondition},
    versioned::versioned,
};
use strum::{Display, EnumIter};

use crate::{
    constant,
    framework::{
        ClusterName, ConfigMapName, ContainerName, ListenerClassName, NameIsValidLabelValue,
        ProductName, RoleName, SecretClassName, role_utils::GenericProductSpecificCommonConfig,
    },
};

constant!(DEFAULT_LISTENER_CLASS: ListenerClassName = "cluster-internal");
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

        // no doc - docs in Role struct
        pub nodes:
            Role<OpenSearchConfigFragment, GenericRoleConfig, GenericProductSpecificCommonConfig>,
    }

    #[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct OpenSearchClusterConfig {
        /// TLS configuration options for the REST API and internal communication (transport).
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
    pub struct OpenSearchTls {
        /// Only affects client connections to the REST API.
        /// This setting controls:
        /// - If TLS encryption is used at all
        /// - Which cert the servers should use to authenticate themselves against the client
        #[serde(
            default = "rest_secret_class_default",
            skip_serializing_if = "Option::is_none"
        )]
        pub rest_secret_class: Option<SecretClassName>,
        /// Only affects internal communication (transport). Used for mutual verification between OpenSearch nodes.
        /// This setting controls:
        /// - Which cert the servers should use to authenticate themselves against other servers
        /// - Which ca.crt to use when validating the other server
        #[serde(default = "transport_secret_class_default")]
        pub transport_secret_class: SecretClassName,
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
            // Default taken from the Helm chart, see
            // https://github.com/opensearch-project/helm-charts/blob/opensearch-3.0.0/charts/opensearch/values.yaml#L364
            graceful_shutdown_timeout: Some(
                Duration::from_str("2m").expect("should be a valid duration"),
            ),
            listener_class: Some(DEFAULT_LISTENER_CLASS.to_owned()),
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
                Duration::from_str("15d").expect("should be a valid duration"),
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

impl Default for v1alpha1::OpenSearchTls {
    fn default() -> Self {
        v1alpha1::OpenSearchTls {
            rest_secret_class: rest_secret_class_default(),
            transport_secret_class: transport_secret_class_default(),
        }
    }
}

fn rest_secret_class_default() -> Option<SecretClassName> {
    Some(TLS_DEFAULT_SECRET_CLASS.to_owned())
}

fn transport_secret_class_default() -> SecretClassName {
    TLS_DEFAULT_SECRET_CLASS.to_owned()
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
        })
        .expect("should be a valid container name")
    }
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
