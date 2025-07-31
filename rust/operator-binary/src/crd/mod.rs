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
    role_utils::{GenericRoleConfig, Role},
    schemars::{self, JsonSchema},
    status::condition::{ClusterCondition, HasStatusCondition},
    time::Duration,
    versioned::versioned,
};
use strum::{Display, EnumIter};

use crate::framework::{
    ClusterName, IsLabelValue, ProductName, RoleName,
    role_utils::GenericProductSpecificCommonConfig,
};

const DEFAULT_LISTENER_CLASS: &str = "cluster-internal";

#[versioned(version(name = "v1alpha1"))]
pub mod versioned {

    /// A OpenSearch cluster stacklet. This resource is managed by the Stackable operator for OpenSearch.
    /// Find more information on how to use it and the resources that the operator generates in the
    /// [operator documentation](DOCS_BASE_URL_PLACEHOLDER/opensearch/).
    #[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[versioned(k8s(
        group = "opensearch.stackable.tech",
        kind = "OpenSearchCluster",
        plural = "opensearchclusters",
        shortname = "opensearch",
        status = "v1alpha1::OpenSearchClusterStatus",
        namespaced,
        crates(
            kube_core = "stackable_operator::kube::core",
            k8s_openapi = "stackable_operator::k8s_openapi",
            schemars = "stackable_operator::schemars"
        )
    ))]
    #[serde(rename_all = "camelCase")]
    pub struct OpenSearchClusterSpec {
        // no doc string - see ProductImage struct
        pub image: ProductImage,

        // no doc string - see ClusterOperation struct
        #[serde(default)]
        pub cluster_operation: ClusterOperation,

        /// OpenSearch nodes
        pub nodes:
            Role<OpenSearchConfigFragment, GenericRoleConfig, GenericProductSpecificCommonConfig>,
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
    pub enum NodeRole {
        // Built-in node roles
        // see https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/node/DiscoveryNodeRole.java#L341-L346

        // TODO https://github.com/Peternator7/strum/issues/113
        #[strum(serialize = "cluster_manager")]
        ClusterManager,
        #[strum(serialize = "coordinating_only")]
        CoordinatingOnly,
        #[strum(serialize = "data")]
        Data,
        #[strum(serialize = "ingest")]
        Ingest,
        #[strum(serialize = "remote_cluster_client")]
        RemoteClusterClient,
        #[strum(serialize = "warm")]
        Warm,

        // Search node role
        // see https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/node/DiscoveryNodeRole.java#L313-L339
        #[strum(serialize = "search")]
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

        pub node_roles: NodeRoles,

        #[fragment_attrs(serde(default))]
        pub resources: Resources<StorageConfig>,

        /// This field controls which [ListenerClass](https://docs.stackable.tech/home/nightly/listener-operator/listenerclass.html) is used to expose the HTTP communication.
        #[fragment_attrs(serde(default))]
        pub listener_class: String,
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
            // Defaults taken from the Helm chart, see
            // https://github.com/opensearch-project/helm-charts/blob/opensearch-3.0.0/charts/opensearch/values.yaml#L16-L20
            node_roles: Some(NodeRoles(vec![
                v1alpha1::NodeRole::ClusterManager,
                v1alpha1::NodeRole::Ingest,
                v1alpha1::NodeRole::Data,
                v1alpha1::NodeRole::RemoteClusterClient,
            ])),
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
            listener_class: Some(DEFAULT_LISTENER_CLASS.to_string()),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct NodeRoles(Vec<v1alpha1::NodeRole>);

impl NodeRoles {
    pub fn contains(&self, node_role: &v1alpha1::NodeRole) -> bool {
        self.0.contains(node_role)
    }

    pub fn iter(&self) -> slice::Iter<v1alpha1::NodeRole> {
        self.0.iter()
    }
}

impl Atomic for NodeRoles {}
