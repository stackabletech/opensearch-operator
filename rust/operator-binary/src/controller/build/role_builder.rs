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
        IsLabelValue,
        builder::{
            meta::ownerreference_from_resource, pdb::pod_disruption_budget_builder_with_role,
        },
        role_utils::ResourceNames,
    },
};

const PDB_DEFAULT_MAX_UNAVAILABLE: u16 = 1;

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

    pub fn build_service_account(&self) -> ServiceAccount {
        let metadata = self.common_metadata(self.resource_names.service_account_name());

        ServiceAccount {
            metadata,
            ..ServiceAccount::default()
        }
    }

    pub fn build_role_binding(&self) -> RoleBinding {
        let metadata = self.common_metadata(self.resource_names.role_binding_name());

        RoleBinding {
            metadata,
            role_ref: RoleRef {
                api_group: ClusterRole::GROUP.to_owned(),
                kind: ClusterRole::KIND.to_owned(),
                name: self.resource_names.cluster_role_name(),
            },
            subjects: Some(vec![Subject {
                api_group: Some(ServiceAccount::GROUP.to_owned()),
                kind: ServiceAccount::KIND.to_owned(),
                name: self.resource_names.service_account_name(),
                namespace: Some(self.cluster.namespace.clone()),
            }]),
        }
    }

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

    /// Labels on role resources
    fn labels(&self) -> Labels {
        // Well-known Kubernetes labels
        let mut labels = Labels::role_selector(
            &self.cluster,
            &self.context_names.product_name.to_label_value(),
            &ValidatedCluster::role_name().to_label_value(),
        )
        .unwrap();

        let managed_by = Label::managed_by(
            &self.context_names.operator_name.to_string(),
            &self.context_names.controller_name.to_string(),
        )
        .unwrap();
        let version = Label::version(&self.cluster.product_version.to_string()).unwrap();

        labels.insert(managed_by);
        labels.insert(version);

        // Stackable-specific labels
        labels
            .parse_insert((STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE))
            .unwrap();

        labels
    }
}
