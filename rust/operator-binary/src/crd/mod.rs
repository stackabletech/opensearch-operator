use std::slice;

use serde::{Deserialize, Serialize};
use stackable_operator::{
    commons::{cluster_operation::ClusterOperation, product_image_selection::ProductImage},
    config::{
        fragment::Fragment,
        merge::{Atomic, Merge},
    },
    kube::CustomResource,
    role_utils::{GenericRoleConfig, Role},
    schemars::{self, JsonSchema},
    status::condition::{ClusterCondition, HasStatusCondition},
    versioned::versioned,
};
use strum::Display;

use crate::framework::role_utils::GenericProductSpecificCommonConfig;

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
        Clone, Debug, Deserialize, Display, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
    )]
    // The OpenSearch configuration uses snake_case. To make it easier to match the log output of
    // OpenSearch with this cluster configuration, snake_case is also used here.
    #[serde(rename_all = "snake_case")]
    pub enum NodeRole {
        // Built-in node roles
        // see https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/node/DiscoveryNodeRole.java#L341-L346

        // TODO https://github.com/Peternator7/strum/issues/113
        #[strum(serialize = "data")]
        Data,
        #[strum(serialize = "ingest")]
        Ingest,
        #[strum(serialize = "cluster_manager")]
        ClusterManager,
        #[strum(serialize = "remote_cluster_client")]
        RemoteClusterClient,
        #[strum(serialize = "warm")]
        Warm,

        // Search node role
        // see https://github.com/opensearch-project/OpenSearch/blob/3.0.0/server/src/main/java/org/opensearch/cluster/node/DiscoveryNodeRole.java#L313-L339
        #[strum(serialize = "search")]
        Search,
    }

    // #[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
    // pub struct NR {
    //     data: Option<()>,
    //     ingest: Option<()>,
    //     cluster_manager: Option<()>,
    //     remote_cluster_client: Option<()>,
    //     warm: Option<()>,
    //     search: Option<()>,
    // }

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
        pub node_roles: NodeRoles,
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

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct NodeRoles(Vec<v1alpha1::NodeRole>);

// impl Iterator for NodeRoles {
//     type Item = v1alpha1::NodeRole;
//
//     fn next(&mut self) -> Option<Self::Item> {
//         self.
//     }
// }

impl NodeRoles {
    pub fn contains(&self, node_role: &v1alpha1::NodeRole) -> bool {
        self.0.contains(node_role)
    }

    pub fn iter(&self) -> slice::Iter<v1alpha1::NodeRole> {
        self.0.iter()
    }
}

impl Atomic for NodeRoles {}
