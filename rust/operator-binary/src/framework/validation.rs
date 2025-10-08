use std::sync::LazyLock;

use regex::Regex;
use snafu::{Snafu, ensure};
use stackable_operator::validation::RFC_1123_SUBDOMAIN_MAX_LENGTH;

/// Format of a key for a ConfigMap or Secret
pub const CONFIG_MAP_KEY_FMT: &str = "[-._a-zA-Z0-9]+";
const CONFIG_MAP_KEY_ERROR_MSG: &str =
    "a valid config key must consist of alphanumeric characters, '-', '_' or '.'";
static CONFIG_MAP_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!("^{CONFIG_MAP_KEY_FMT}$")).expect("failed to compile ConfigMap key regex")
});

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("value does not match the regular expression"))]
    Regex {
        value: String,
        regex: &'static str,
        message: &'static str,
    },

    #[snafu(display("value exceeds the maximum length"))]
    TooLong { value: String, max_length: usize },
}

type Result = std::result::Result<(), Error>;

/// Tests if the given value is a valid key for a ConfigMap or Secret
///
/// see <https://github.com/kubernetes/kubernetes/blob/v1.34.1/staging/src/k8s.io/apimachinery/pkg/util/validation/validation.go#L435>
pub fn is_config_map_key(value: &str) -> Result {
    // When adding this function to stackable_operator, use the private functions like
    // validate_all.

    let max_length = RFC_1123_SUBDOMAIN_MAX_LENGTH;
    ensure!(
        value.len() < max_length,
        TooLongSnafu {
            value: value.to_owned(),
            max_length
        }
    );

    ensure!(
        CONFIG_MAP_KEY_REGEX.is_match(value),
        RegexSnafu {
            value: value.to_owned(),
            regex: CONFIG_MAP_KEY_FMT,
            message: CONFIG_MAP_KEY_ERROR_MSG
        }
    );

    Ok(())
}
