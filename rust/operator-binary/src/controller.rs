use std::sync::Arc;

use const_format::concatcp;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{PodBuilder, container::ContainerBuilder},
    },
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{Container, PodTemplateSpec},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kube::{
        Resource,
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    kvp::{Labels, ObjectLabels},
    logging::controller::ReconcilerError,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    OPERATOR_NAME,
    crd::v1alpha1::{self, OpenSearchClusterStatus},
};

const CONTROLLER_NAME: &str = "opensearchcluster";
pub const FULL_CONTROLLER_NAME: &str = concatcp!(CONTROLLER_NAME, '.', OPERATOR_NAME);
const APP_NAME: &str = "opensearch";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("OpenSearchCluster object is invalid"))]
    InvalidOpenSearchCluster {
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub fn error_policy(
    _obj: Arc<DeserializeGuard<v1alpha1::OpenSearchCluster>>,
    error: &Error,
    _ctx: Arc<Ctx>,
) -> Action {
    match error {
        // root object is invalid, will be requed when modified
        Error::InvalidOpenSearchCluster { .. } => Action::await_change(),
        _ => Action::requeue(*Duration::from_secs(5)),
    }
}

pub async fn reconcile(
    opensearch: Arc<DeserializeGuard<v1alpha1::OpenSearchCluster>>,
    ctx: Arc<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let opensearch = opensearch
        .0
        .as_ref()
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidOpenSearchClusterSnafu)?;

    let client = &ctx.client;

    let mut cluster_resources = ClusterResources::new(
        APP_NAME,
        OPERATOR_NAME,
        CONTROLLER_NAME,
        &opensearch.object_ref(&()),
        ClusterResourceApplyStrategy::from(&opensearch.spec.cluster_operation),
    )
    .context(CreateClusterResourcesSnafu)?;

    let mut ss_cond_builder = StatefulSetConditionBuilder::default();

    let statefulset = build_statefulset(opensearch);

    ss_cond_builder.add(cluster_resources.add(client, statefulset).await.unwrap());

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&opensearch.spec.cluster_operation);

    let status = OpenSearchClusterStatus {
        conditions: compute_conditions(
            opensearch,
            &[&ss_cond_builder, &cluster_operation_cond_builder],
        ),
        discovery_hash: None,
    };

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;

    client
        .apply_patch_status(OPERATOR_NAME, opensearch, &status)
        .await
        .context(ApplyStatusSnafu)?;

    Ok(Action::await_change())
}

fn build_statefulset(opensearch: &v1alpha1::OpenSearchCluster) -> StatefulSet {
    let metadata = ObjectMetaBuilder::new()
        .name_and_namespace(opensearch)
        .with_recommended_labels(ObjectLabels {
            owner: opensearch,
            app_name: APP_NAME,
            app_version: "3.0.0",
            operator_name: OPERATOR_NAME,
            controller_name: CONTROLLER_NAME,
            role: "node",
            role_group: "default",
        })
        .unwrap()
        .build();

    let template = build_pod_template(opensearch);

    let statefulset_match_labels =
        Labels::role_group_selector(opensearch, APP_NAME, "node", "default").unwrap();

    let spec = StatefulSetSpec {
        // Order does not matter for OpenSearch
        pod_management_policy: Some("Parallel".to_string()),
        replicas: Some(1),
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

fn build_pod_template(opensearch: &v1alpha1::OpenSearchCluster) -> PodTemplateSpec {
    let mut builder = PodBuilder::new();

    let metadata = ObjectMetaBuilder::new()
        .with_recommended_labels(ObjectLabels {
            owner: opensearch,
            app_name: APP_NAME,
            app_version: "3.0.0",
            operator_name: OPERATOR_NAME,
            controller_name: CONTROLLER_NAME,
            role: "node",
            role_group: "default",
        })
        .unwrap()
        .build();

    let container = build_container();

    builder
        .metadata(metadata)
        .add_container(container)
        .build_template()
}

fn build_container() -> Container {
    ContainerBuilder::new("opensearch")
        .expect("ContainerBuilder not created")
        .image("opensearchproject/opensearch:3.0.0")
        .add_env_var("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "super@Secret1")
        .add_env_var("cluster.initial_master_nodes", "opensearch-0")
        .build()
}
