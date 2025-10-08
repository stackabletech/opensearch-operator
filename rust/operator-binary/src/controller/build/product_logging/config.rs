use std::cmp;

use stackable_operator::{
    memory::{BinaryMultiple, MemoryQuantity},
    product_logging::spec::AutomaticContainerLogConfig,
};

use crate::{crd::v1alpha1, framework::product_logging::framework::STACKABLE_LOG_DIR};

/// The log configuration file
pub const CONFIGURATION_FILE_LOG4J2_PROPERTIES: &str = "log4j2.properties";

const OPENSEARCH_SERVER_LOG_FILE: &str = "opensearch_server.json";

pub const MAX_OPENSEARCH_SERVER_LOG_FILES_SIZE: MemoryQuantity = MemoryQuantity {
    value: 10.0,
    unit: BinaryMultiple::Mebi,
};

pub fn create_log4j2_config(config: &AutomaticContainerLogConfig) -> String {
    let log_path = format!(
        "{STACKABLE_LOG_DIR}/{container}/{OPENSEARCH_SERVER_LOG_FILE}",
        container = v1alpha1::Container::OpenSearch.to_container_name()
    );

    let number_of_archived_log_files = 1;
    let max_log_files_size_in_mib = MAX_OPENSEARCH_SERVER_LOG_FILES_SIZE
        .scale_to(BinaryMultiple::Mebi)
        .floor()
        .value as u32;
    let max_log_file_size_in_mib = cmp::max(
        1,
        max_log_files_size_in_mib / (1 + number_of_archived_log_files),
    );

    let loggers = config
        .loggers
        .iter()
        .filter(|(name, _)| name.as_str() != AutomaticContainerLogConfig::ROOT_LOGGER)
        .enumerate()
        .flat_map(|(index, (name, logger_config))| {
            [
                (
                    format!("logger.{index}.name"),
                    name.escape_default().to_string(),
                ),
                (
                    format!("logger.{index}.level"),
                    logger_config.level.to_log4j_literal(),
                ),
            ]
        })
        .collect::<Vec<_>>();

    let root_logger = vec![
        (
            "rootLogger.level".to_owned(),
            config.root_log_level().to_log4j2_literal(),
        ),
        (
            "rootLogger.appenderRef.CONSOLE.ref".to_owned(),
            "CONSOLE".to_owned(),
        ),
        (
            "rootLogger.appenderRef.FILE.ref".to_owned(),
            "FILE".to_owned(),
        ),
    ];

    let console_appender = vec![
        ("appender.CONSOLE.type".to_owned(), "Console".to_owned()),
        ("appender.CONSOLE.name".to_owned(), "CONSOLE".to_owned()),
        (
            "appender.CONSOLE.target".to_owned(),
            "SYSTEM_ERR".to_owned(),
        ),
        (
            "appender.CONSOLE.layout.type".to_owned(),
            "PatternLayout".to_owned(),
        ),
        // Same as the default layout pattern of the console appender
        // see https://github.com/opensearch-project/OpenSearch/blob/3.1.0/distribution/src/config/log4j2.properties#L17
        (
            "appender.CONSOLE.layout.pattern".to_owned(),
            "[%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n".to_owned(),
        ),
        (
            "appender.CONSOLE.filter.threshold.type".to_owned(),
            "ThresholdFilter".to_owned(),
        ),
        (
            "appender.CONSOLE.filter.threshold.level".to_owned(),
            config
                .console
                .as_ref()
                .and_then(|console| console.level)
                .unwrap_or_default()
                .to_log4j2_literal(),
        ),
    ];

    let file_appender = vec![
        ("appender.FILE.type".to_owned(), "RollingFile".to_owned()),
        ("appender.FILE.name".to_owned(), "FILE".to_owned()),
        ("appender.FILE.fileName".to_owned(), log_path.to_owned()),
        (
            "appender.FILE.filePattern".to_owned(),
            format!("{log_path}.%i"),
        ),
        (
            "appender.FILE.layout.type".to_owned(),
            "OpenSearchJsonLayout".to_owned(),
        ),
        (
            "appender.FILE.layout.type_name".to_owned(),
            "server".to_owned(),
        ),
        (
            "appender.FILE.policies.type".to_owned(),
            "Policies".to_owned(),
        ),
        (
            "appender.FILE.policies.size.type".to_owned(),
            "SizeBasedTriggeringPolicy".to_owned(),
        ),
        (
            "appender.FILE.policies.size.size".to_owned(),
            format!("{max_log_file_size_in_mib}MB"),
        ),
        (
            "appender.FILE.strategy.type".to_owned(),
            "DefaultRolloverStrategy".to_owned(),
        ),
        (
            "appender.FILE.strategy.max".to_owned(),
            number_of_archived_log_files.to_string(),
        ),
        (
            "appender.FILE.filter.threshold.type".to_owned(),
            "ThresholdFilter".to_owned(),
        ),
        (
            "appender.FILE.filter.threshold.level".to_owned(),
            config
                .file
                .as_ref()
                .and_then(|file| file.level)
                .unwrap_or_default()
                .to_log4j2_literal(),
        ),
    ];

    [root_logger, loggers, console_appender, file_appender]
        .iter()
        .flatten()
        .map(|(key, value)| format!("{key} = {value}\n"))
        .collect()
}

pub fn vector_config_file_content() -> String {
    include_str!("vector.yaml").to_owned()
}

#[cfg(test)]
mod tests {
    use stackable_operator::product_logging::spec::{
        AppenderConfig, AutomaticContainerLogConfig, LogLevel, LoggerConfig,
    };

    use super::create_log4j2_config;

    #[test]
    pub fn test_create_log4j2_config() {
        let log4j2_config = create_log4j2_config(&AutomaticContainerLogConfig {
            loggers: [
                (
                    "org.opensearch.index.reindex".to_owned(),
                    LoggerConfig {
                        level: LogLevel::DEBUG,
                    },
                ),
                (
                    "org.opensearch.indices.recovery".to_owned(),
                    LoggerConfig {
                        level: LogLevel::TRACE,
                    },
                ),
            ]
            .into(),
            console: Some(AppenderConfig {
                level: Some(LogLevel::WARN),
            }),
            file: Some(AppenderConfig {
                level: Some(LogLevel::DEBUG),
            }),
        });

        let expected_config = concat!(
                "rootLogger.level = INFO\n",
                "rootLogger.appenderRef.CONSOLE.ref = CONSOLE\n",
                "rootLogger.appenderRef.FILE.ref = FILE\n",
                "logger.0.name = org.opensearch.index.reindex\n",
                "logger.0.level = DEBUG\n",
                "logger.1.name = org.opensearch.indices.recovery\n",
                "logger.1.level = TRACE\n",
                "appender.CONSOLE.type = Console\n",
                "appender.CONSOLE.name = CONSOLE\n",
                "appender.CONSOLE.target = SYSTEM_ERR\n",
                "appender.CONSOLE.layout.type = PatternLayout\n",
                "appender.CONSOLE.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n\n",
                "appender.CONSOLE.filter.threshold.type = ThresholdFilter\n",
                "appender.CONSOLE.filter.threshold.level = WARN\n",
                "appender.FILE.type = RollingFile\n",
                "appender.FILE.name = FILE\n",
                "appender.FILE.fileName = /stackable/log/opensearch/opensearch_server.json\n",
                "appender.FILE.filePattern = /stackable/log/opensearch/opensearch_server.json.%i\n",
                "appender.FILE.layout.type = OpenSearchJsonLayout\n",
                "appender.FILE.layout.type_name = server\n",
                "appender.FILE.policies.type = Policies\n",
                "appender.FILE.policies.size.type = SizeBasedTriggeringPolicy\n",
                "appender.FILE.policies.size.size = 5MB\n",
                "appender.FILE.strategy.type = DefaultRolloverStrategy\n",
                "appender.FILE.strategy.max = 1\n",
                "appender.FILE.filter.threshold.type = ThresholdFilter\n",
                "appender.FILE.filter.threshold.level = DEBUG\n",
            ).to_owned();

        assert_eq!(expected_config, log4j2_config);
    }
}
