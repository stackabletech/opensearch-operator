use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::api::{
        core::v1::{Service, ServicePort, ServiceSpec},
        policy::v1::PodDisruptionBudget,
    },
    kvp::{
        Label, Labels,
        consts::{STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE},
    },
};

use super::role_group_builder::{
    HTTP_PORT, HTTP_PORT_NAME, METRICS_PORT, METRICS_PORT_NAME, RoleGroupBuilder, TRANSPORT_PORT,
    TRANSPORT_PORT_NAME,
};
use crate::{
    controller::{ContextNames, ValidatedCluster},
    crd::v1alpha1,
    framework::{
        ClusterName, OBJECT_NAME_MAX_LENGTH, RoleName,
        builder::{
            meta::ownerreference_from_resource, pdb::pod_disruption_budget_builder_with_role,
        },
    },
};

const PDB_DEFAULT_MAX_UNAVAILABLE: u16 = 1;

pub struct RoleBuilder<'a> {
    names: &'a ContextNames,
    role_name: RoleName,
    cluster: ValidatedCluster,
}

impl<'a> RoleBuilder<'a> {
    pub fn new(
        names: &'a ContextNames,
        role_name: RoleName,
        cluster: ValidatedCluster,
    ) -> RoleBuilder<'a> {
        RoleBuilder {
            names,
            role_name: role_name.clone(),
            cluster: cluster.clone(),
        }
    }

    pub fn role_group_builders(&self) -> Vec<RoleGroupBuilder> {
        self.cluster
            .role_group_configs
            .iter()
            .map(|(role_group_name, role_group_config)| {
                RoleGroupBuilder::new(
                    self.names,
                    self.role_name.clone(),
                    self.cluster.clone(),
                    role_group_name.clone(),
                    role_group_config.clone(),
                    self.discovery_service_name(),
                )
            })
            .collect()
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
            ServicePort {
                name: Some(METRICS_PORT_NAME.to_owned()),
                port: METRICS_PORT.into(),
                ..ServicePort::default()
            },
        ];

        // Well-known Kubernetes labels
        let mut labels = Labels::role_selector(
            &self.cluster,
            &self.names.product_name.to_string(),
            &self.role_name.to_string(),
        )
        .unwrap();

        let managed_by = Label::managed_by(
            &self.names.operator_name.to_string(),
            &self.names.controller_name.to_string(),
        )
        .unwrap();
        let version = Label::version(&self.cluster.product_version.to_string()).unwrap();

        labels.insert(managed_by);
        labels.insert(version);

        // Stackable-specific labels
        labels
            .parse_insert((STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE))
            .unwrap();

        let metadata = ObjectMetaBuilder::new()
            .name(self.discovery_service_name())
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(labels)
            .build();

        let service_selector = [(
            v1alpha1::NodeRole::ClusterManager.to_string(),
            "true".to_owned(),
        )]
        .into();

        let service_spec = ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(ports),
            selector: Some(service_selector),
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
                    &self.names.product_name,
                    &self.role_name,
                    &self.names.operator_name,
                    &self.names.controller_name,
                )
                .with_max_unavailable(max_unavailable)
                .build(),
            )
        } else {
            None
        }
    }

    fn discovery_service_name(&self) -> String {
        const SUFFIX: &str = "-cluster-manager";

        // Compile-time check
        const _: () = assert!(
            ClusterName::MAX_LENGTH + SUFFIX.len() <= OBJECT_NAME_MAX_LENGTH,
            "The resource name `<cluster_name>-cluster-manager` must not exceed 253 characters."
        );

        format!("{}{SUFFIX}", self.cluster.name)
    }
}
