//! Builder for role resources

use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::{
        Resource,
        api::{
            core::v1::{Service, ServiceAccount, ServicePort, ServiceSpec},
            policy::v1::PodDisruptionBudget,
            rbac::v1::{ClusterRole, RoleBinding, RoleRef, Subject},
        },
    },
    kube::api::ObjectMeta,
    kvp::{
        Label, Labels,
        consts::{STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE},
    },
};

use super::role_group_builder::{
    HTTP_PORT, HTTP_PORT_NAME, RoleGroupBuilder, TRANSPORT_PORT, TRANSPORT_PORT_NAME,
};
use crate::{
    controller::{ContextNames, ValidatedCluster},
    framework::{
        NameIsValidLabelValue,
        builder::{
            meta::ownerreference_from_resource, pdb::pod_disruption_budget_builder_with_role,
        },
        role_utils::ResourceNames,
    },
};

const PDB_DEFAULT_MAX_UNAVAILABLE: u16 = 1;

/// Builder for role resources
pub struct RoleBuilder<'a> {
    cluster: ValidatedCluster,
    context_names: &'a ContextNames,
    resource_names: ResourceNames,
}

impl<'a> RoleBuilder<'a> {
    pub fn new(cluster: ValidatedCluster, context_names: &'a ContextNames) -> RoleBuilder<'a> {
        RoleBuilder {
            cluster: cluster.clone(),
            context_names,
            resource_names: ResourceNames {
                cluster_name: cluster.name.clone(),
                product_name: context_names.product_name.clone(),
            },
        }
    }

    /// Creates role-group builders which are initialized with the role-level context
    pub fn role_group_builders(&self) -> Vec<RoleGroupBuilder<'_>> {
        self.cluster
            .role_group_configs
            .iter()
            .map(|(role_group_name, role_group_config)| {
                RoleGroupBuilder::new(
                    self.resource_names.service_account_name(),
                    self.cluster.clone(),
                    role_group_name.clone(),
                    role_group_config.clone(),
                    self.context_names,
                    self.resource_names.discovery_service_name(),
                )
            })
            .collect()
    }

    /// Builds a ServiceAccount used by all role-groups
    pub fn build_service_account(&self) -> ServiceAccount {
        let metadata = self.common_metadata(self.resource_names.service_account_name());

        ServiceAccount {
            metadata,
            ..ServiceAccount::default()
        }
    }

    /// Builds a RoleBinding used by all role-groups
    pub fn build_role_binding(&self) -> RoleBinding {
        let metadata = self.common_metadata(self.resource_names.role_binding_name());

        RoleBinding {
            metadata,
            role_ref: RoleRef {
                api_group: ClusterRole::GROUP.to_owned(),
                kind: ClusterRole::KIND.to_owned(),
                name: self.resource_names.cluster_role_name().to_string(),
            },
            subjects: Some(vec![Subject {
                api_group: Some(ServiceAccount::GROUP.to_owned()),
                kind: ServiceAccount::KIND.to_owned(),
                name: self.resource_names.service_account_name().to_string(),
                namespace: Some(self.cluster.namespace.to_string()),
            }]),
        }
    }

    /// Builds a Service that references all nodes with the cluster_manager node role
    ///
    /// Initially, this service was meant to be used by
    /// [`super::node_config::NodeConfig::initial_cluster_manager_nodes`], but the function uses now another approach.
    /// Afterwards, it was meant to be used as an entry point to OpenSearch, but it could also make
    /// sense to use coordinating only nodes as entry points and not cluster manager nodes.
    /// Therefore, this service will bei either adapted or removed. There is already an according
    /// task entry in <https://github.com/stackabletech/opensearch-operator/issues/1>.
    pub fn build_cluster_manager_service(&self) -> Service {
        let ports = vec![
            ServicePort {
                name: Some(HTTP_PORT_NAME.to_owned()),
                port: HTTP_PORT.into(),
                ..ServicePort::default()
            },
            ServicePort {
                name: Some(TRANSPORT_PORT_NAME.to_owned()),
                port: TRANSPORT_PORT.into(),
                ..ServicePort::default()
            },
        ];

        let metadata = self.common_metadata(self.resource_names.discovery_service_name());

        let service_selector =
            RoleGroupBuilder::cluster_manager_labels(&self.cluster, self.context_names);

        let service_spec = ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(ports),
            selector: Some(service_selector.into()),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        };

        Service {
            metadata,
            spec: Some(service_spec),
            status: None,
        }
    }

    /// Builds a [`PodDisruptionBudget`] used by all role-groups
    pub fn build_pdb(&self) -> Option<PodDisruptionBudget> {
        let pdb_config = &self.cluster.role_config.pod_disruption_budget;

        if pdb_config.enabled {
            let max_unavailable = pdb_config
                .max_unavailable
                .unwrap_or(PDB_DEFAULT_MAX_UNAVAILABLE);
            Some(
                pod_disruption_budget_builder_with_role(
                    &self.cluster,
                    &self.context_names.product_name,
                    &ValidatedCluster::role_name(),
                    &self.context_names.operator_name,
                    &self.context_names.controller_name,
                )
                .with_max_unavailable(max_unavailable)
                .build(),
            )
        } else {
            None
        }
    }

    /// Common metadata for role resources
    fn common_metadata(&self, resource_name: impl Into<String>) -> ObjectMeta {
        ObjectMetaBuilder::new()
            .name(resource_name)
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(self.labels())
            .build()
    }

    /// Common labels for role resources
    fn labels(&self) -> Labels {
        // Well-known Kubernetes labels
        let mut labels = Labels::role_selector(
            &self.cluster,
            &self.context_names.product_name.to_label_value(),
            &ValidatedCluster::role_name().to_label_value(),
        )
        .unwrap();

        let managed_by = Label::managed_by(
            self.context_names.operator_name.as_ref(),
            self.context_names.controller_name.as_ref(),
        )
        .unwrap();
        let version = Label::version(self.cluster.product_version.as_ref()).unwrap();

        labels.insert(managed_by);
        labels.insert(version);

        // Stackable-specific labels
        labels
            .parse_insert((STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE))
            .unwrap();

        labels
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        str::FromStr,
    };

    use pretty_assertions::assert_eq;
    use serde_json::json;
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
    };
    use uuid::uuid;

    use super::RoleBuilder;
    use crate::{
        controller::{
            ContextNames, OpenSearchRoleGroupConfig, ValidatedCluster,
            ValidatedContainerLogConfigChoice, ValidatedLogging, ValidatedOpenSearchConfig,
        },
        crd::{NodeRoles, v1alpha1},
        framework::{
            builder::pod::container::EnvVarSet,
            role_utils::GenericProductSpecificCommonConfig,
            types::{
                kubernetes::{ListenerClassName, NamespaceName},
                operator::{
                    ClusterName, ControllerName, OperatorName, ProductName, ProductVersion,
                    RoleGroupName,
                },
            },
        },
    };

    fn context_names() -> ContextNames {
        ContextNames {
            product_name: ProductName::from_str_unsafe("opensearch"),
            operator_name: OperatorName::from_str_unsafe("opensearch.stackable.tech"),
            controller_name: ControllerName::from_str_unsafe("opensearchcluster"),
        }
    }

    fn role_builder<'a>(context_names: &'a ContextNames) -> RoleBuilder<'a> {
        let image: ProductImage = serde_json::from_str(r#"{"productVersion": "3.1.0"}"#)
            .expect("should be a valid ProductImage");

        let role_group_config = OpenSearchRoleGroupConfig {
            replicas: 1,
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
                resources: Resources::default(),
                termination_grace_period_seconds: 30,
            },
            config_overrides: HashMap::default(),
            env_overrides: EnvVarSet::default(),
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
        );

        RoleBuilder::new(cluster, context_names)
    }

    #[test]
    fn test_build_service_account() {
        let context_names = context_names();
        let role_builder = role_builder(&context_names);

        let service_account = serde_json::to_value(role_builder.build_service_account())
            .expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "my-opensearch-cluster-serviceaccount",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "opensearch.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "OpenSearchCluster",
                            "name": "my-opensearch-cluster",
                            "uid": "0b1e30e6-326e-4c1a-868d-ad6598b49e8b"
                        }
                    ]
                }
            }),
            service_account
        );
    }

    #[test]
    fn test_build_role_binding() {
        let context_names = context_names();
        let role_builder = role_builder(&context_names);

        let role_binding = serde_json::to_value(role_builder.build_role_binding())
            .expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "my-opensearch-cluster-rolebinding",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "opensearch.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "OpenSearchCluster",
                            "name": "my-opensearch-cluster",
                            "uid": "0b1e30e6-326e-4c1a-868d-ad6598b49e8b"
                        }
                    ]
                },
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "opensearch-clusterrole"
                },
                "subjects": [
                    {
                        "apiGroup": "",
                        "kind": "ServiceAccount",
                        "name": "my-opensearch-cluster-serviceaccount",
                        "namespace": "default"
                    }
                ]
            }),
            role_binding
        );
    }

    #[test]
    fn test_build_cluster_manager_service() {
        let context_names = context_names();
        let role_builder = role_builder(&context_names);

        let cluster_manager_service =
            serde_json::to_value(role_builder.build_cluster_manager_service())
                .expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch",
                        "app.kubernetes.io/version": "3.1.0",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "my-opensearch-cluster-discovery",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "opensearch.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "OpenSearchCluster",
                            "name": "my-opensearch-cluster",
                            "uid": "0b1e30e6-326e-4c1a-868d-ad6598b49e8b"
                        }
                    ]
                },
                "spec": {
                    "clusterIP": "None",
                    "ports": [
                        {
                            "name": "http",
                            "port": 9200
                        },
                        {
                            "name": "transport",
                            "port": 9300
                        }
                    ],
                    "publishNotReadyAddresses": true,
                    "selector": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/name": "opensearch",
                        "stackable.tech/opensearch-role.cluster_manager": "true"
                    },
                    "type": "ClusterIP"
                }
            }),
            cluster_manager_service
        );
    }

    #[test]
    fn test_build_pdb() {
        let context_names = context_names();
        let role_builder = role_builder(&context_names);

        let pdb = serde_json::to_value(role_builder.build_pdb()).expect("should be serializable");

        assert_eq!(
            json!({
                "apiVersion": "policy/v1",
                "kind": "PodDisruptionBudget",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/component": "nodes",
                        "app.kubernetes.io/instance": "my-opensearch-cluster",
                        "app.kubernetes.io/managed-by": "opensearch.stackable.tech_opensearchcluster",
                        "app.kubernetes.io/name": "opensearch"
                    },
                    "name": "my-opensearch-cluster-nodes",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "opensearch.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "OpenSearchCluster",
                            "name": "my-opensearch-cluster",
                            "uid": "0b1e30e6-326e-4c1a-868d-ad6598b49e8b"
                        }
                    ]
                },
                "spec": {
                    "maxUnavailable": 1,
                    "selector": {
                        "matchLabels": {
                            "app.kubernetes.io/component": "nodes",
                            "app.kubernetes.io/instance": "my-opensearch-cluster",
                            "app.kubernetes.io/name": "opensearch"
                        }
                    }
                }
            }),
            pdb
        );
    }
}
