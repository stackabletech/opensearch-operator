#!/usr/bin/env sh

DATA_DIR=/stackable/log/_vector-state \
LOG_DIR=/stackable/log \
OPENSEARCH_SERVER_LOG_FILE=opensearch_server.json \
NAMESPACE=default \
CLUSTER_NAME=opensearch \
ROLE_NAME=nodes \
ROLE_GROUP_NAME=cluster-manager \
VECTOR_AGGREGATOR_ADDRESS=vector-aggregator \
VECTOR_FILE_LOG_LEVEL=info \
vector test vector.yaml vector-test.yaml
