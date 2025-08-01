# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

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

[#10]: https://github.com/stackabletech/opensearch-operator/pull/10
[#17]: https://github.com/stackabletech/opensearch-operator/pull/17
[#18]: https://github.com/stackabletech/opensearch-operator/pull/18
