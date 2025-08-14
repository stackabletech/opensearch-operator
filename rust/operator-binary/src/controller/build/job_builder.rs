use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{container::ContainerBuilder, resources::ResourceRequirementsBuilder},
    },
    k8s_openapi::api::{
        batch::v1::{Job, JobSpec},
        core::v1::{
            PodSecurityContext, PodSpec, PodTemplateSpec, SecretVolumeSource, Volume, VolumeMount,
        },
    },
    kube::api::ObjectMeta,
    kvp::{
        Label, Labels,
        consts::{STACKABLE_VENDOR_KEY, STACKABLE_VENDOR_VALUE},
    },
};

use crate::{
    controller::{ContextNames, ValidatedCluster},
    framework::{
        IsLabelValue, builder::meta::ownerreference_from_resource, role_utils::ResourceNames,
    },
};

const RUN_SECURITYADMIN_CERT_VOLUME_NAME: &str = "tls";
const RUN_SECURITYADMIN_CERT_VOLUME_MOUNT: &str = "/stackable/cert";
const SECURITY_CONFIG_VOLUME_NAME: &str = "security-config";
const SECURITY_CONFIG_VOLUME_MOUNT: &str = "/stackable/opensearch/config/opensearch-security";
const RUN_SECURITYADMIN_CONTAINER_NAME: &str = "run-securityadmin";

pub struct JobBuilder<'a> {
    cluster: ValidatedCluster,
    context_names: &'a ContextNames,
    resource_names: ResourceNames,
}

impl<'a> JobBuilder<'a> {
    pub fn new(cluster: ValidatedCluster, context_names: &'a ContextNames) -> JobBuilder<'a> {
        JobBuilder {
            cluster: cluster.clone(),
            context_names,
            resource_names: ResourceNames {
                cluster_name: cluster.name.clone(),
                product_name: context_names.product_name.clone(),
            },
        }
    }

    pub fn build_run_securityadmin_job(&self) -> Job {
        let product_image = self
            .cluster
            .image
            .resolve("opensearch", crate::built_info::PKG_VERSION);
        // Maybe add a suffix for consecutive
        let metadata = self.common_metadata(format!(
            "{}-run-securityadmin",
            self.resource_names.cluster_name,
        ));

        let args = [
            "plugins/opensearch-security/tools/securityadmin.sh".to_string(),
            "-cacert".to_string(),
            "config/tls-client/ca.crt".to_string(),
            "-cert".to_string(),
            "config/tls-client/tls.crt".to_string(),
            "-key".to_string(),
            "config/tls-client/tls.key".to_string(),
            "--hostname".to_string(),
            self.opensearch_master_fqdn(),
            "--configdir".to_string(),
            "config/opensearch-security/".to_string(),
        ];
        let mut cb = ContainerBuilder::new(RUN_SECURITYADMIN_CONTAINER_NAME)
            .expect("should be a valid container name");
        let container = cb
            .image_from_product_image(&product_image)
            .command(vec!["sh".to_string(), "-c".to_string()])
            .args(vec![args.join(" ")])
            // The VolumeMount for the secret operator key store certificates
            .add_volume_mounts([
                VolumeMount {
                    mount_path: RUN_SECURITYADMIN_CERT_VOLUME_MOUNT.to_owned(),
                    name: RUN_SECURITYADMIN_CERT_VOLUME_NAME.to_owned(),
                    ..VolumeMount::default()
                },
                VolumeMount {
                    mount_path: SECURITY_CONFIG_VOLUME_MOUNT.to_owned(),
                    name: SECURITY_CONFIG_VOLUME_NAME.to_owned(),
                    ..VolumeMount::default()
                },
            ])
            .expect("the mount paths are statically defined and there should be no duplicates")
            .resources(
                ResourceRequirementsBuilder::new()
                    .with_cpu_request("100m")
                    .with_cpu_limit("400m")
                    .with_memory_request("128Mi")
                    .with_memory_limit("512Mi")
                    .build(),
            )
            .build();

        let pod_template = PodTemplateSpec {
            metadata: Some(metadata.clone()),
            spec: Some(PodSpec {
                containers: vec![container],

                security_context: Some(PodSecurityContext {
                    fs_group: Some(1000),
                    ..PodSecurityContext::default()
                }),
                service_account_name: Some(self.resource_names.service_account_name()),
                volumes: Some(vec![Volume {
                    name: SECURITY_CONFIG_VOLUME_NAME.to_owned(),
                    secret: Some(SecretVolumeSource {
                        secret_name: Some("opensearch-security-config".to_string()),
                        ..Default::default()
                    }),
                    ..Volume::default()
                }]),
                ..PodSpec::default()
            }),
        };

        Job {
            metadata,
            spec: Some(JobSpec {
                backoff_limit: Some(100),
                ttl_seconds_after_finished: Some(120),
                template: pod_template,
                ..JobSpec::default()
            }),
            ..Job::default()
        }
    }

    fn opensearch_master_fqdn(&self) -> String {
        let cluster_manager_service_name = self.resource_names.discovery_service_name();
        let namespace = &self.cluster.namespace;
        let cluster_domain = &self.context_names.cluster_domain_name;
        format!("{cluster_manager_service_name}.{namespace}.svc.{cluster_domain}")
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
