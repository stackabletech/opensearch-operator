use serde::{Deserialize, Serialize};
use stackable_operator::{
    commons::{cluster_operation::ClusterOperation, product_image_selection::ProductImage},
    config::{fragment::Fragment, merge::Merge},
    kube::{CustomResource, ResourceExt},
    role_utils::Role,
    schemars::{self, JsonSchema},
    status::condition::{ClusterCondition, HasStatusCondition},
    versioned::versioned,
};

use crate::framework::ToLabelValue;

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
        // no doc string - See ProductImage struct
        pub image: ProductImage,

        // no doc string - See ClusterOperation struct
        #[serde(default)]
        pub cluster_operation: ClusterOperation,

        // Only one role here!
        pub nodes: Role<OpenSearchConfigFragment>,
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

impl ToLabelValue for v1alpha1::OpenSearchCluster {
    fn to_label_value(&self) -> String {
        // opinionated!
        self.name_unchecked()
    }
}

// TODO Perhaps rename to InstanceConfig
#[derive(Clone, Debug, Default, Fragment, JsonSchema, PartialEq)]
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
pub struct OpenSearchConfig {}
