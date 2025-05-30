use std::sync::Arc;

use snafu::Snafu;
use stackable_operator::{
    kube::{
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    logging::controller::ReconcilerError,
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::crd::v1alpha1;

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

    Ok(Action::await_change())
}
