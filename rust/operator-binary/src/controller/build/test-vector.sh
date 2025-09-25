#!/usr/bin/env sh

LOG_DIR=/stackable/log \
OPENSEARCH_SERVER_LOG_FILE=opensearch_server.json \
NAMESPACE=default \
CLUSTER_NAME=opensearch \
ROLE_NAME=nodes \
ROLE_GROUP_NAME=cluster-manager \
VECTOR_AGGREGATOR=vector-aggregator \
VECTOR_FILE_LOG_LEVEL=info \
vector test vector.yaml vector-test.yaml
