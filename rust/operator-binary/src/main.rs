use clap::Parser as _;
use crd::OpenSearchCluster;
use snafu::{ResultExt as _, Snafu};
use stackable_operator::{
    YamlSchema as _,
    cli::{Command, ProductOperatorRun},
    shared::yaml::SerializeOptions,
    telemetry::Tracing,
};
use strum::{EnumDiscriminants, IntoStaticStr};

mod crd;

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
            OpenSearchCluster::merged_crd(OpenSearchCluster::V1Alpha1)
                .context(MergeCrdSnafu)?
                .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())
                .context(SerializeCrdSnafu)?;
        }
        Command::Run(ProductOperatorRun {
            product_config: _,
            watch_namespace: _,
            telemetry_arguments,
            cluster_info_opts: _,
        }) => {
            let _tracing_guard = Tracing::pre_configured(built_info::PKG_NAME, telemetry_arguments)
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
        }
    }

    Ok(())
}
