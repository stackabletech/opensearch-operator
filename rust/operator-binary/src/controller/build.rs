use std::str::FromStr;

use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{PodBuilder, container::ContainerBuilder},
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{Container, PodTemplateSpec},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kvp::Labels,
};

use super::{
    APP_NAME, CONTROLLER_NAME, Prepared, Resources, RoleGroupConfig, RoleGroupName,
    ValidatedCluster,
};
use crate::{
    OPERATOR_NAME,
    framework::{
        AppName, ControllerName, OperatorName, RoleName,
        kvp::label::{recommended_labels, role_group_selector},
        to_qualified_role_group_name,
    },
};

pub struct Builder {
    app_name: AppName,
    operator_name: OperatorName,
    controller_name: ControllerName,
    role_name: RoleName,
    cluster: ValidatedCluster,
}

impl Builder {
    pub fn new(cluster: ValidatedCluster) -> Builder {
        Builder {
            // into controller context!
            app_name: AppName::from_str(APP_NAME).unwrap(),
            role_name: RoleName::from_str("nodes").unwrap(),
            operator_name: OperatorName::from_str(OPERATOR_NAME).unwrap(),
            controller_name: ControllerName::from_str(CONTROLLER_NAME).unwrap(),
            cluster,
        }
    }

    pub fn build(&self) -> Resources<Prepared> {
        let mut resources = Resources::new();
        for (role_group_name, role_group_config) in self.cluster.role_group_configs.iter() {
            resources
                .stateful_sets
                .push(self.build_statefulset(role_group_name, role_group_config));
        }
        resources
    }

    fn build_statefulset(
        &self,
        role_group_name: &RoleGroupName,
        role_group_config: &RoleGroupConfig,
    ) -> StatefulSet {
        let metadata = ObjectMetaBuilder::new()
            .name(to_qualified_role_group_name(
                &self.cluster.name,
                &self.role_name,
                role_group_name,
            ))
            .namespace(&self.cluster.namespace)
            .with_labels(self.build_recommended_labels(role_group_name))
            .build();

        let template = self.build_pod_template(role_group_name);

        let statefulset_match_labels = role_group_selector(
            &self.cluster,
            &self.app_name,
            &self.role_name,
            role_group_name,
        );

        let spec = StatefulSetSpec {
            // Order does not matter for OpenSearch
            pod_management_policy: Some("Parallel".to_string()),
            replicas: role_group_config.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(statefulset_match_labels.into()),
                ..LabelSelector::default()
            },
            service_name: None,
            template,
            ..StatefulSetSpec::default()
        };

        StatefulSet {
            metadata,
            spec: Some(spec),
            status: None,
        }
    }

    fn build_pod_template(&self, role_group_name: &RoleGroupName) -> PodTemplateSpec {
        let mut builder = PodBuilder::new();

        let metadata = ObjectMetaBuilder::new()
            .with_labels(self.build_recommended_labels(role_group_name))
            .build();

        let container = self.build_container();

        builder
            .metadata(metadata)
            .add_container(container)
            .build_template()
    }

    fn build_container(&self) -> Container {
        let product_image = self
            .cluster
            .image
            .resolve("opensearch", crate::built_info::PKG_VERSION);

        // TODO ContainerName as typed string?
        ContainerBuilder::new("opensearch")
            .expect("ContainerBuilder not created")
            .image_from_product_image(&product_image)
            .add_env_var("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "super@Secret1")
            .add_env_var("cluster.initial_master_nodes", "opensearch-0")
            .build()
    }

    fn build_recommended_labels(&self, role_group_name: &RoleGroupName) -> Labels {
        recommended_labels(
            &self.cluster,
            &self.app_name,
            &self.cluster.product_version,
            &self.operator_name,
            &self.controller_name,
            &self.role_name,
            role_group_name,
        )
    }
}
