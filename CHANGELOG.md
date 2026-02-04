# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Allow the configuration of TLS for the HTTP and TRANSPORT ports with the operator ([#55]).
- Add the role group as a node attribute ([#63]).
- Allow adding entries to the OpenSearch keystore ([#76]).
- Support objectOverrides using `.spec.objectOverrides`.
  See [objectOverrides concepts page](https://docs.stackable.tech/home/nightly/concepts/overrides/#object-overrides) for details ([#93]).
- Enable the [restart-controller](https://docs.stackable.tech/home/nightly/commons-operator/restarter/), so that the Pods are automatically restarted on config changes ([#97]).
- Configure OpenSearch to publish the fully-qualified domain names of the nodes instead of the IP
  addresses, so that TLS certificates can be verified ([#100]).
- Add service discovery and exposition ([#94]):
  - Service to set up the cluster renamed to `<cluster-name>-seed-nodes`.
  - Discovery service named `<cluster-name>`, added.
    The discovery service is used to populate the discovery ConfigMap.
  - Discovery ConfigMap named `<cluster-name>`, added.
    The ConfigMap contains the keys `OPENSEARCH_HOSTNAME`, `OPENSEARCH_PORT`, `OPENSEARCH_PROTOCOL`
    and `OPENSEARCH_HOSTS`. Users should use this information to connect to the cluster.
  - Configuration parameter `spec.nodes.roleConfig.discoveryServiceListenerClass` added to set the
    ListenerClass for the discovery service.
  - Configuration parameter `spec.nodes.roleGroups.<role-group-name>.config.discoveryServiceExposed`
    added to expose a role-group via the discovery service.
- Add support for OpenSearch 3.4.0 ([#108]).

### Changed

- Gracefully shutdown all concurrent tasks by forwarding the SIGTERM signal ([#110]).
- Bump testing-tools to `0.3.0-stackable0.0.0-dev` ([#91]).

### Fixed

- Log file rollover fixed ([#107]).

[#55]: https://github.com/stackabletech/opensearch-operator/pull/55
[#63]: https://github.com/stackabletech/opensearch-operator/pull/63
[#76]: https://github.com/stackabletech/opensearch-operator/pull/76
[#91]: https://github.com/stackabletech/opensearch-operator/pull/91
[#93]: https://github.com/stackabletech/opensearch-operator/pull/93
[#94]: https://github.com/stackabletech/opensearch-operator/pull/94
[#97]: https://github.com/stackabletech/opensearch-operator/pull/97
[#100]: https://github.com/stackabletech/opensearch-operator/pull/100
[#107]: https://github.com/stackabletech/opensearch-operator/pull/107
[#108]: https://github.com/stackabletech/opensearch-operator/pull/108
[#110]: https://github.com/stackabletech/opensearch-operator/pull/110

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
