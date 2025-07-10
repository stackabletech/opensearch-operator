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

    // TODO Only one builder function which calls the other ones?

    pub fn role_group_builders(&self) -> Vec<RoleGroupBuilder> {
        self.cluster
            .role_group_configs
            .iter()
            .map(|(role_group_name, role_group_config)| {
                RoleGroupBuilder::new(
                    self.names,
                    self.role_name.clone(),
                    self.service_account_name(),
                    self.cluster.clone(),
                    role_group_name.clone(),
                    role_group_config.clone(),
                    self.discovery_service_name(),
                )
            })
            .collect()
    }

    pub fn build_service_account(&self) -> ServiceAccount {
        // TODO Move to a common create_meta function
        let metadata = ObjectMetaBuilder::new()
            .name(self.service_account_name())
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(self.labels())
            .build();

        ServiceAccount {
            metadata,
            ..ServiceAccount::default()
        }
    }

    pub fn build_role_binding(&self) -> RoleBinding {
        // TODO Move to a common create_meta function
        let metadata = ObjectMetaBuilder::new()
            .name(self.role_binding_name())
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(self.labels())
            .build();

        RoleBinding {
            metadata,
            role_ref: RoleRef {
                api_group: ClusterRole::GROUP.to_owned(),
                kind: ClusterRole::KIND.to_owned(),
                name: self.cluster_role_name(),
            },
            subjects: Some(vec![Subject {
                api_group: Some(ServiceAccount::GROUP.to_owned()),
                kind: ServiceAccount::KIND.to_owned(),
                name: self.service_account_name(),
                namespace: Some(self.cluster.namespace.clone()),
            }]),
        }
    }

    /// Labels on role resources
    fn labels(&self) -> Labels {
        // TODO Are the labels stackable.tech/name and stackable.tech/instance missing?

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

        labels
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

        let metadata = ObjectMetaBuilder::new()
            .name(self.discovery_service_name())
            .namespace(&self.cluster.namespace)
            .ownerreference(ownerreference_from_resource(
                &self.cluster,
                None,
                Some(true),
            ))
            .with_labels(self.labels())
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

    fn service_account_name(&self) -> String {
        const SUFFIX: &str = "-serviceaccount";

        // Compile-time check
        const _: () = assert!(
            ClusterName::MAX_LENGTH + SUFFIX.len() <= OBJECT_NAME_MAX_LENGTH,
            "The resource name `<cluster_name>-serviceaccount` must not exceed 253 characters."
        );

        format!("{}{SUFFIX}", self.cluster.name)
    }

    fn role_binding_name(&self) -> String {
        const SUFFIX: &str = "-rolebinding";

        // Compile-time check
        const _: () = assert!(
            ClusterName::MAX_LENGTH + SUFFIX.len() <= OBJECT_NAME_MAX_LENGTH,
            "The resource name `<cluster_name>-rolebinding` must not exceed 253 characters."
        );

        format!("{}{SUFFIX}", self.cluster.name)
    }

    fn cluster_role_name(&self) -> String {
        const SUFFIX: &str = "-clusterrole";

        // Compile-time check
        const _: () = assert!(
            ClusterName::MAX_LENGTH + SUFFIX.len() <= OBJECT_NAME_MAX_LENGTH,
            "The resource name `<product_name>-clusterrole` must not exceed 253 characters."
        );

        format!("{}{SUFFIX}", self.names.product_name)
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
