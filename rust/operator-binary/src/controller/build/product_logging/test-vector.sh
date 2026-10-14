#!/usr/bin/env sh

set -eu

export DATA_DIR=/stackable/log/_vector-state
export LOG_DIR=/stackable/log
export OPENSEARCH_SERVER_LOG_FILE=opensearch_server.json
export NAMESPACE=default
export CLUSTER_NAME=opensearch
export ROLE_NAME=nodes
export ROLE_GROUP_NAME=cluster-manager
export VECTOR_AGGREGATOR_ADDRESS=http://vector-aggregator:6000
export VECTOR_FILE_LOG_LEVEL=info

# Required because vector.yaml contains ${...} placeholders
export VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true

vector validate --no-environment vector.yaml

vector test vector.yaml vector-test.yaml
