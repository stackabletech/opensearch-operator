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

#[derive(Debug, Eq, PartialEq, Snafu)]
pub enum Error {
    #[snafu(display("value is empty"))]
    Empty { value: String },

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

    ensure!(!value.is_empty(), EmptySnafu { value });

    let max_length = RFC_1123_SUBDOMAIN_MAX_LENGTH;
    ensure!(
        value.len() <= max_length,
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

#[cfg(test)]
mod tests {
    use super::{CONFIG_MAP_KEY_ERROR_MSG, CONFIG_MAP_KEY_FMT, Error, is_config_map_key};

    #[test]
    fn test_is_config_map_key() {
        assert_eq!(Ok(()), is_config_map_key("_a-A.1"));

        assert_eq!(
            Err(Error::Empty {
                value: "".to_owned()
            }),
            is_config_map_key("")
        );

        assert_eq!(Ok(()), is_config_map_key(&"a".repeat(253)));
        assert_eq!(
            Err(Error::TooLong {
                value: "a".repeat(254),
                max_length: 253
            }),
            is_config_map_key(&"a".repeat(254))
        );

        assert_eq!(
            Err(Error::Regex {
                value: " ".to_string(),
                regex: CONFIG_MAP_KEY_FMT,
                message: CONFIG_MAP_KEY_ERROR_MSG,
            }),
            is_config_map_key(" ")
        );
    }
}
