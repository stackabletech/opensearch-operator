#! /usr/bin/env bash
set -euo pipefail

# DO NOT EDIT THE SCRIPT
# Instead, update the j2 template, and regenerate it for dev with `make render-docs`.

# This script contains all the code snippets from the guide, as well as some assert tests
# to test if the instructions in the guide work. The user *could* use it, but it is intended
# for testing only.
# The script will install the operators, create a OpenSearch instance and briefly open a port
# forward and connect to the OpenSearch instance to make sure it is up and running.
# No running processes are left behind (i.e. the port-forwarding is closed at the end)

if [ $# -eq 0 ]
then
  echo "Installation method argument ('helm' or 'stackablectl') required."
  exit 1
fi

cd "$(dirname "$0")"

case "$1" in
"helm")
echo "Installing Operators with Helm"
# tag::helm-install-operators[]
helm install --wait commons-operator oci://oci.stackable.tech/sdp-charts/commons-operator --version 25.11.0
helm install --wait secret-operator oci://oci.stackable.tech/sdp-charts/secret-operator --version 25.11.0
helm install --wait listener-operator oci://oci.stackable.tech/sdp-charts/listener-operator --version 25.11.0
helm install --wait opensearch-operator oci://oci.stackable.tech/sdp-charts/opensearch-operator --version 25.11.0
# end::helm-install-operators[]
;;
"stackablectl")
echo "installing Operators with stackablectl"
# tag::stackablectl-install-operators[]
stackablectl operator install \
  commons=25.11.0 \
  secret=25.11.0 \
  listener=25.11.0 \
  opensearch=25.11.0
# end::stackablectl-install-operators[]
;;
*)
echo "Need to give 'helm' or 'stackablectl' as an argument for which installation method to use!"
exit 1
;;
esac

echo "Creating OpenSearch security plugin configuration"
# tag::apply-security-config[]
kubectl apply -f opensearch-security-config.yaml
# end::apply-security-config[]

echo "Creating OpenSearch cluster"
# tag::apply-cluster[]
kubectl apply -f opensearch.yaml
# end::apply-cluster[]

sleep 5

for (( i=1; i<=15; i++ ))
do
  echo "Waiting for OpenSearchCluster to appear ..."
  if eval kubectl get statefulset simple-opensearch-nodes-default; then
    break
  fi

  sleep 1
done

echo "Waiting on OpenSearch StatefulSet ..."
# tag::await-cluster[]
kubectl rollout status --watch statefulset/simple-opensearch-nodes-default --timeout 600s
# end::await-cluster[]

# wait a bit for the port to open
sleep 10

echo "Starting port-forwarding of port 9200"
# tag::opensearch-port-forwarding[]
kubectl port-forward services/simple-opensearch 9200 > /dev/null 2>&1 &
# end::opensearch-port-forwarding[]
PORT_FORWARD_PID=$!
# shellcheck disable=2064 # we want the PID evaluated now, not at the time the trap is
trap "kill $PORT_FORWARD_PID" EXIT
sleep 5

echo "Using the REST API"
# tag::rest-api[]
export CREDENTIALS=admin:AJVFsGJBbpT6mChn

curl \
    --insecure \
    --user $CREDENTIALS \
    --request PUT \
    --json '{"name": "Stackable"}' \
    https://localhost:9200/sample_index/_doc/1

# Output:
# {"_index":"sample_index","_id":"1","_version":1,"result":"created","_shards":{"total":2,"successful":1,"failed":0},"_seq_no":0,"_primary_term":1}

curl \
    --insecure \
    --user $CREDENTIALS \
    --request GET \
    https://localhost:9200/sample_index/_doc/1

# Output:
# {"_index":"sample_index","_id":"1","_version":1,"_seq_no":0,"_primary_term":1,"found":true,"_source":{"name": "Stackable"}}
# end::rest-api[]

echo
echo "Using OpenSearch Dashboards"
# tag::opensearch-dashboards[]
kubectl create secret generic opensearch-credentials \
    --from-literal kibanaserver=E4kENuEmkqH3jyHC

helm install opensearch-dashboards opensearch-dashboards \
    --repo https://opensearch-project.github.io/helm-charts \
    --version 3.1.0 \
    --values opensearch-dashboards-values.yaml \
    --wait
# end::opensearch-dashboards[]

echo "Starting port-forwarding of port 5601"
# tag::opensearch-dashboards-port-forwarding[]
kubectl port-forward services/opensearch-dashboards 5601 > /dev/null 2>&1 &
# end::opensearch-dashboards-port-forwarding[]
PORT_FORWARD_PID=$!
# shellcheck disable=2064 # we want the PID evaluated now, not at the time the trap is
trap "kill $PORT_FORWARD_PID" EXIT
sleep 600
