# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Add the role group as a node attribute ([#63]).

[#63]: https://github.com/stackabletech/opensearch-operator/pull/63

## [25.11.0] - 2025-11-07

## [25.11.0-rc1] - 2025-11-06

### Added

- Add end-of-support checker which can be controlled with environment variables and CLI arguments ([#38]).
  - `EOS_CHECK_MODE` (`--eos-check-mode`) to set the EoS check mode. Currently, only "offline" is supported.
  - `EOS_INTERVAL` (`--eos-interval`) to set the interval in which the operator checks if it is EoS.
  - `EOS_DISABLED` (`--eos-disabled`) to disable the EoS checker completely.
- Basic operator for OpenSearch 3.x with the following configuration options ([#10]):
  - Cluster operations like `reconciliationPaused` and `stopped`
  - Image selection (defaults to the official OpenSearch image for now)
  - Overrides (CLI, config, environment variables, Pod)
  - Affinities
  - Graceful shutdown timeout
  - OpenSearch node roles
  - Resources (CPU, memory, storage)
  - PodDisruptionBudgets
  - Replicas
- Add Listener support ([#17]).
- Make the environment variables `OPENSEARCH_HOME` and `OPENSEARCH_PATH_CONF` overridable, so that
  images can be used which have a different directory structure than the Stackable image ([#18]).
- Add Prometheus labels and annotations to role-group services ([#26]).
- Helm: Allow Pod `priorityClassName` to be configured ([#34]).
- Support log configuration and log aggregation ([#40]).
- Ensure that the permissions of the configuration files are correct ([#47]).

### Changed

- Bump stackable-operator to `0.100.1` ([#58]).

[#10]: https://github.com/stackabletech/opensearch-operator/pull/10
[#17]: https://github.com/stackabletech/opensearch-operator/pull/17
[#18]: https://github.com/stackabletech/opensearch-operator/pull/18
[#26]: https://github.com/stackabletech/opensearch-operator/pull/26
[#34]: https://github.com/stackabletech/opensearch-operator/pull/34
[#38]: https://github.com/stackabletech/opensearch-operator/pull/38
[#40]: https://github.com/stackabletech/opensearch-operator/pull/40
[#47]: https://github.com/stackabletech/opensearch-operator/pull/47
[#58]: https://github.com/stackabletech/opensearch-operator/pull/58
