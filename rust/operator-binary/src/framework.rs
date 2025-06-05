// Type-safe wrappers that cannot throw errors
// The point is, to move the validation "upwards".

use std::str::FromStr;

use snafu::{ResultExt, Snafu};
use stackable_operator::kvp::{LabelValue, LabelValueError};
use strum::{EnumDiscriminants, IntoStaticStr};

pub mod kvp;

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to use as label"))]
    InvalidLabelName { source: LabelValueError },
}

pub trait ToLabelValue {
    fn to_label_value(&self) -> String;
}

macro_rules! typed_string {
    ($name:ident) => {
        #[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl ToLabelValue for $name {
            fn to_label_value(&self) -> String {
                self.0.clone()
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                LabelValue::from_str(s).context(InvalidLabelNameSnafu)?;
                Ok(Self(s.to_owned()))
            }
        }
    };
}

typed_string!(AppName);
typed_string!(AppVersion);
typed_string!(ControllerName);
typed_string!(OperatorName);
typed_string!(RoleGroupName);
typed_string!(RoleName);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::framework::AppName;

    #[test]
    fn test_typed_string_constraints() {
        assert!(AppName::from_str("valid-role-group-name").is_ok());
        assert!(AppName::from_str("invalid-character: /").is_err());
        assert!(
            AppName::from_str(
                "too-long-123456789012345678901234567890123456789012345678901234567890"
            )
            .is_err()
        );
    }
}
