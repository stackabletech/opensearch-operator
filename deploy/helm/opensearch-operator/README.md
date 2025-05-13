<!-- markdownlint-disable MD034 -->
# Helm Chart for Stackable Operator for OpenSearch

This Helm Chart can be used to install Custom Resource Definitions and the Operator for OpenSearch provided by Stackable.

## Requirements

- Create a [Kubernetes Cluster](../Readme.md)
- Install [Helm](https://helm.sh/docs/intro/install/)

## Install the Stackable Operator for OpenSearch

```bash
# From the root of the operator repository
make compile-chart

helm install opensearch-operator deploy/helm/opensearch-operator
```

## Usage of the CRDs

The usage of this operator and its CRDs is described in the [documentation](https://docs.stackable.tech/opensearch/index.html)

The operator has example requests included in the [`/examples`](https://github.com/stackabletech/opensearch-operator/tree/main/examples) directory.

## Links

<https://github.com/stackabletech/opensearch-operator>
