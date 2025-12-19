use snafu::{ResultExt, Snafu};
use strum::{EnumDiscriminants, IntoStaticStr};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to convert to port number"))]
    ConvertToPortNumber { source: std::num::TryFromIntError },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Port(pub u16);

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<i32> for Port {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(Port(
            u16::try_from(value).context(ConvertToPortNumberSnafu)?,
        ))
    }
}

impl From<Port> for i32 {
    fn from(value: Port) -> Self {
        value.0 as i32
    }
}
