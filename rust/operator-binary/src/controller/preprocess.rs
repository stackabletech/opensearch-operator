//! The preprocess step in the OpenSearchCluster controller

use stackable_operator::{
    commons::resources::{PvcConfigFragment, ResourcesFragment},
    k8s_openapi::apimachinery::pkg::api::resource::Quantity,
    role_utils::CommonConfiguration,
};
use tracing::info;

use crate::crd::{NodeRoles, OpenSearchRoleGroup, v1alpha1};

/// Preprocesses the OpenSearchCluster and adds configurations that the user is allowed to leave
/// out
pub fn preprocess(cluster: v1alpha1::OpenSearchCluster) -> v1alpha1::OpenSearchCluster {
    preprocess_security_managing_role_group(cluster)
}

/// Adds the role group defined in [`v1alpha1::Security::managing_role_group`] if the OpenSearch
/// security plugin is enabled, any security settings are managed by the operator and the defined
/// role group does not exist yet
pub fn preprocess_security_managing_role_group(
    mut cluster: v1alpha1::OpenSearchCluster,
) -> v1alpha1::OpenSearchCluster {
    let security = &cluster.spec.cluster_config.security;
    if security.enabled
        && !security.settings.is_only_managed_by_api()
        && !cluster
            .spec
            .nodes
            .role_groups
            .contains_key(&security.managing_role_group.to_string())
    {
        info!(
            "The security configuration is managed by the role group \"{role_group}\". \
            This role group was not specified explicitly and will be created.",
            role_group = security.managing_role_group
        );

        let role_group = OpenSearchRoleGroup {
            config: CommonConfiguration {
                config: v1alpha1::OpenSearchConfigFragment {
                    discovery_service_exposed: Some(false),
                    node_roles: Some(NodeRoles(vec![v1alpha1::NodeRole::CoordinatingOnly])),
                    resources: ResourcesFragment {
                        storage: v1alpha1::StorageConfigFragment {
                            data: PvcConfigFragment {
                                capacity: Some(Quantity("100Mi".to_owned())),
                                ..PvcConfigFragment::default()
                            },
                        },
                        ..ResourcesFragment::default()
                    },
                    ..v1alpha1::OpenSearchConfigFragment::default()
                },
                ..CommonConfiguration::default()
            },
            replicas: Some(1),
        };

        cluster
            .spec
            .nodes
            .role_groups
            .insert(security.managing_role_group.to_string(), role_group);
    }

    cluster
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use pretty_assertions::assert_eq;
    use serde_json::json;

    use crate::controller::preprocess::preprocess;

    #[test]
    fn test_preprocess_security_managing_role_group() {
        let cluster_spec = json!({
            "apiVersion": "opensearch.stackable.tech/v1alpha1",
            "kind": "OpenSearchCluster",
            "metadata": {
                "name": "opensearch",
                "namespace": "default",
                "uid": "e6ac237d-a6d4-43a1-8135-f36506110912"
            },
            "spec": {
                "image": {
                    "productVersion": "3.4.0"
                },
                "clusterConfig": {
                    "security": {
                        "managingRoleGroup": "security-manager",
                        "settings": {
                            "config": {
                                "managedBy": "operator",
                                "content": {
                                    "valueFrom": {
                                        "configMapKeyRef": {
                                            "name": "opensearch-security-config",
                                            "key": "config.yml"
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "nodes": {
                    "roleGroups": {
                        "default": {
                            "replicas": 1
                        }
                    }
                }
            }
        });

        let cluster = serde_json::from_value(cluster_spec).expect("should be deserializable");
        let prepocessed_cluster = preprocess(cluster);

        let expected_role_groups_spec = json!({
            "default": {
                "replicas": 1
            },
            "security-manager": {
                "config" : {
                    "discoveryServiceExposed": false,
                    "nodeRoles": [
                        "coordinating_only"
                    ],
                    "resources": {
                        "storage": {
                            "data": {
                                "capacity": "100Mi"
                            }
                        }
                    }
                },
                "replicas": 1
            }
        });
        let expected_role_groups: HashMap<_, _> =
            serde_json::from_value(expected_role_groups_spec).expect("should be deserializable");

        assert_eq!(
            expected_role_groups,
            prepocessed_cluster.spec.nodes.role_groups
        );
    }
}
