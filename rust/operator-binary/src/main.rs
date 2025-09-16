use std::{str::FromStr, sync::Arc};

use clap::Parser as _;
use crd::{OpenSearchCluster, OpenSearchClusterVersion, v1alpha1};
use framework::OperatorName;
use futures::StreamExt;
use snafu::{ResultExt as _, Snafu};
use stackable_operator::{
    YamlSchema as _,
    cli::{Command, CommonOptions, ProductOperatorRun},
    k8s_openapi::api::{apps::v1::StatefulSet, core::v1::Service},
    kube::{
        core::DeserializeGuard,
        runtime::{
            Controller,
            events::{Recorder, Reporter},
            watcher,
        },
    },
    logging::controller::report_controller_reconciled,
    shared::yaml::SerializeOptions,
    telemetry::Tracing,
};
use strum::{EnumDiscriminants, IntoStaticStr};

mod controller;
mod crd;
mod framework;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to initialize tracing subscribers"))]
    InitTracing {
        source: stackable_operator::telemetry::tracing::Error,
    },

    #[snafu(display("failed to merge CRD versions"))]
    MergeCrd {
        source: stackable_operator::kube::core::crd::MergeError,
    },

    #[snafu(display("failed to serialize CRD"))]
    SerializeCrd {
        source: stackable_operator::shared::yaml::Error,
    },

    #[snafu(display("failed to create Kubernetes client"))]
    CreateClient {
        source: stackable_operator::client::Error,
    },
}

#[derive(clap::Parser)]
#[clap(about, author)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[tokio::main]
#[snafu::report]
async fn main() -> Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        Command::Crd => {
            OpenSearchCluster::merged_crd(OpenSearchClusterVersion::V1Alpha1)
                .context(MergeCrdSnafu)?
                .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())
                .context(SerializeCrdSnafu)?;
        }
        Command::Run(ProductOperatorRun {
            common:
                CommonOptions {
                    telemetry,
                    cluster_info,
                },
            disable_crd_maintenance: _,
            operator_environment: _,
            product_config: _,
            watch_namespace,
        }) => {
            let _tracing_guard = Tracing::pre_configured(built_info::PKG_NAME, telemetry)
                .init()
                .context(InitTracingSnafu)?;

            tracing::info!(
                built_info.pkg_version = built_info::PKG_VERSION,
                built_info.git_version = built_info::GIT_VERSION,
                built_info.target = built_info::TARGET,
                built_info.built_time_utc = built_info::BUILT_TIME_UTC,
                built_info.rustc_version = built_info::RUSTC_VERSION,
                "Starting {description}",
                description = built_info::PKG_DESCRIPTION
            );

            let operator_name = OperatorName::from_str("opensearch.stackable.tech")
                .expect("should be a valid operator name");

            let client = stackable_operator::client::initialize_operator(
                Some(format!("{operator_name}")),
                &cluster_info,
            )
            .await
            .context(CreateClientSnafu)?;

            let controller_context = controller::Context::new(client.clone(), operator_name);
            let full_controller_name = controller_context.full_controller_name();

            let event_recorder = Arc::new(Recorder::new(
                client.as_kube_client(),
                Reporter {
                    controller: full_controller_name.clone(),
                    instance: None,
                },
            ));

            let controller = Controller::new(
                watch_namespace.get_api::<DeserializeGuard<v1alpha1::OpenSearchCluster>>(&client),
                watcher::Config::default(),
            );
            controller
                .owns(
                    watch_namespace.get_api::<Service>(&client),
                    watcher::Config::default(),
                )
                .owns(
                    watch_namespace.get_api::<StatefulSet>(&client),
                    watcher::Config::default(),
                )
                .shutdown_on_signal()
                .run(
                    controller::reconcile,
                    controller::error_policy,
                    Arc::new(controller_context),
                )
                .for_each_concurrent(
                    16, // concurrency limit
                    |result| {
                        // The event_recorder needs to be shared across all invocations, so that
                        // events are correctly aggregated
                        let event_recorder = event_recorder.clone();
                        let full_controller_name = full_controller_name.clone();
                        async move {
                            report_controller_reconciled(
                                &event_recorder,
                                &full_controller_name,
                                &result,
                            )
                            .await;
                        }
                    },
                )
                .await;
        }
    }

    Ok(())
}
