# =============
# This file is automatically generated from the templates in stackabletech/operator-templating
# DO NOT MANUALLY EDIT THIS FILE
# =============

# This script requires https://github.com/mikefarah/yq (not to be confused with https://github.com/kislyuk/yq)
# It is available from Nixpkgs as `yq-go` (`nix shell nixpkgs#yq-go`)
# This script also requires `jq` https://stedolan.github.io/jq/

.PHONY: build publish

TAG    := $(shell git rev-parse --short HEAD)
OPERATOR_NAME := opensearch-operator
VERSION := $(shell cargo metadata --format-version 1 | jq -r '.packages[] | select(.name=="stackable-${OPERATOR_NAME}") | .version')
ARCH := $(shell uname -m | sed -e 's#x86_64#amd64#' | sed -e 's#aarch64#arm64#')

OCI_REGISTRY_HOSTNAME := oci.stackable.tech
OCI_REGISTRY_PROJECT_IMAGES := sdp
OCI_REGISTRY_PROJECT_CHARTS := sdp-charts
# This will be overwritten by an environmental variable if called from the github action
HELM_CHART_NAME := ${OPERATOR_NAME}
HELM_CHART_ARTIFACT := target/helm/${OPERATOR_NAME}-${VERSION}.tgz

SHELL=/usr/bin/env bash -euo pipefail

render-readme:
	scripts/render_readme.sh

render-docs:
	scripts/docs_templating.sh

## Docker related targets
docker-build:
	docker build --force-rm --build-arg VERSION=${VERSION} -t "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}-${ARCH}" -f docker/Dockerfile .

docker-publish:
	# Push to Harbor
	# We need to use "value" here to prevent the variable from being recursively expanded by make (username contains a dollar sign, since it's a Harbor bot)
	docker login --username '${value OCI_REGISTRY_SDP_USERNAME}' --password '${OCI_REGISTRY_SDP_PASSWORD}' '${OCI_REGISTRY_HOSTNAME}'
	DOCKER_OUTPUT=$$(docker push --all-tags '${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}');\
	# Obtain the digest of the pushed image from the output of `docker push`, because signing by tag is deprecated and will be removed from cosign in the future\
	REPO_DIGEST_OF_IMAGE=$$(echo "$$DOCKER_OUTPUT" | awk '/^${VERSION}-${ARCH}: digest: sha256:[0-9a-f]{64} size: [0-9]+$$/ { print $$3 }');\
	if [ -z "$$REPO_DIGEST_OF_IMAGE" ]; then\
		echo 'Could not find repo digest for container image: ${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}-${ARCH}';\
		exit 1;\
	fi;\
	# This generates a signature and publishes it to the registry, next to the image\
	# Uses the keyless signing flow with Github Actions as identity provider\
	cosign sign -y "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}@$$REPO_DIGEST_OF_IMAGE";\
	# Generate the SBOM for the operator image, this leverages the already generated SBOM for the operator binary by cargo-cyclonedx\
	syft scan --output cyclonedx-json@1.5=sbom.json --select-catalogers "-cargo-auditable-binary-cataloger,+sbom-cataloger" --scope all-layers --source-name "${OPERATOR_NAME}" --source-version "${VERSION}-${ARCH}" "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}@$$REPO_DIGEST_OF_IMAGE";\
	# Determine the PURL for the container image\
	URLENCODED_REPO_DIGEST_OF_IMAGE=$$(echo "$$REPO_DIGEST_OF_IMAGE" | sed 's/:/%3A/g');\
	PURL="pkg:oci/${OPERATOR_NAME}@$$URLENCODED_REPO_DIGEST_OF_IMAGE?arch=${ARCH}&repository_url=${OCI_REGISTRY_HOSTNAME}%2F${OCI_REGISTRY_PROJECT_IMAGES}%2F${OPERATOR_NAME}";\
	# Get metadata from the image\
	IMAGE_DESCRIPTION=$$(docker inspect --format='{{.Config.Labels.description}}' "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}-${ARCH}");\
	IMAGE_NAME=$$(docker inspect --format='{{.Config.Labels.name}}' "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}-${ARCH}");\
	# Merge the SBOM with the metadata for the operator\
	jq -s '{"metadata":{"component":{"description":"'"$$IMAGE_NAME. $$IMAGE_DESCRIPTION"'","supplier":{"name":"Stackable GmbH","url":["https://stackable.tech/"]},"author":"Stackable GmbH","purl":"'"$$PURL"'","publisher":"Stackable GmbH"}}} * .[0]' sbom.json > sbom.merged.json;\
	# Attest the SBOM to the image\
	cosign attest -y --predicate sbom.merged.json --type cyclonedx "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}@$$REPO_DIGEST_OF_IMAGE"

# This assumes "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}-amd64 and "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}-arm64 are built and pushed
docker-manifest-list-build:
	docker manifest create "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}" --amend "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}-amd64" --amend "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}-arm64"

docker-manifest-list-publish:
	# Push to Harbor
	# We need to use "value" here to prevent the variable from being recursively expanded by make (username contains a dollar sign, since it's a Harbor bot)
	docker login --username '${value OCI_REGISTRY_SDP_USERNAME}' --password '${OCI_REGISTRY_SDP_PASSWORD}' '${OCI_REGISTRY_HOSTNAME}'
	DIGEST_HARBOR=$$(docker manifest push "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}");\
	# Refer to image via its digest (oci.stackable.tech/sdp/airflow@sha256:0a1b2c...);\
	# This generates a signature and publishes it to the registry, next to the image\
	# Uses the keyless signing flow with Github Actions as identity provider\
	cosign sign -y "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}@$$DIGEST_HARBOR"

# TODO remove if not used/needed
docker: docker-build docker-publish

print-docker-tag:
	@echo "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}"

helm-publish:
	# Push to Harbor
	# We need to use "value" here to prevent the variable from being recursively expanded by make (username contains a dollar sign, since it's a Harbor bot)
	helm registry login --username '${value OCI_REGISTRY_SDP_CHARTS_USERNAME}' --password '${OCI_REGISTRY_SDP_CHARTS_PASSWORD}' '${OCI_REGISTRY_HOSTNAME}'
	# Obtain the digest of the pushed artifact from the output of `helm push`, because signing by tag is deprecated and will be removed from cosign in the future\
	HELM_OUTPUT=$$(helm push '${HELM_CHART_ARTIFACT}' 'oci://${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_CHARTS}' 2>&1);\
	REPO_DIGEST_OF_ARTIFACT=$$(echo "$$HELM_OUTPUT" | awk '/^Digest: sha256:[0-9a-f]{64}$$/ { print $$2 }');\
	if [ -z "$$REPO_DIGEST_OF_ARTIFACT" ]; then\
		echo 'Could not find repo digest for helm chart: ${HELM_CHART_NAME}';\
		exit 1;\
	fi;\
	# Login to Harbor, needed for cosign to be able to push the signature for the Helm chart\
	docker login --username '${value OCI_REGISTRY_SDP_CHARTS_USERNAME}' --password '${OCI_REGISTRY_SDP_CHARTS_PASSWORD}' '${OCI_REGISTRY_HOSTNAME}';\
	# This generates a signature and publishes it to the registry, next to the chart artifact\
	# Uses the keyless signing flow with Github Actions as identity provider\
	cosign sign -y "${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_CHARTS}/${HELM_CHART_NAME}@$$REPO_DIGEST_OF_ARTIFACT"

helm-package:
	mkdir -p target/helm && helm package --destination target/helm deploy/helm/${OPERATOR_NAME}

## Chart related targets
compile-chart: version crds config

chart-clean:
	rm -rf "deploy/helm/${OPERATOR_NAME}/configs"
	rm -rf "deploy/helm/${OPERATOR_NAME}/crds"

version:
	cat "deploy/helm/${OPERATOR_NAME}/Chart.yaml" | yq ".version = \"${VERSION}\" | .appVersion = \"${VERSION}\"" > "deploy/helm/${OPERATOR_NAME}/Chart.yaml.new"
	mv "deploy/helm/${OPERATOR_NAME}/Chart.yaml.new" "deploy/helm/${OPERATOR_NAME}/Chart.yaml"

config:
	if [ -d "deploy/config-spec/" ]; then\
		mkdir -p "deploy/helm/${OPERATOR_NAME}/configs";\
		cp -r deploy/config-spec/* "deploy/helm/${OPERATOR_NAME}/configs";\
	fi

crds:
	mkdir -p deploy/helm/"${OPERATOR_NAME}"/crds
	cargo run --bin stackable-"${OPERATOR_NAME}" -- crd | yq eval '.metadata.annotations["helm.sh/resource-policy"]="keep"' - > "deploy/helm/${OPERATOR_NAME}/crds/crds.yaml"

chart-lint: compile-chart
	docker run -it -v $(shell pwd):/build/helm-charts -w /build/helm-charts quay.io/helmpack/chart-testing:v3.5.0  ct lint --config deploy/helm/ct.yaml

clean: chart-clean
	cargo clean
	docker rmi --force '${OCI_REGISTRY_HOSTNAME}/${OCI_REGISTRY_PROJECT_IMAGES}/${OPERATOR_NAME}:${VERSION}'

regenerate-charts: chart-clean compile-chart

regenerate-nix:
	nix run --extra-experimental-features "nix-command flakes" -f . regenerateNixLockfiles

build: regenerate-charts regenerate-nix helm-package docker-build

# This target is used by the CI
# It doesn't make use of any nix dependencies and thus aviods building the
# operator unnecessarily often.
build-ci: regenerate-charts helm-package docker-build

publish: docker-publish helm-publish

check-nix:
	@which nix || (echo "Error: 'nix' is not installed. Please install it to proceed."; exit 1)

check-kubernetes:
	@kubectl cluster-info > /dev/null 2>&1 || (echo "Error: Kubernetes is not running or kubectl is not properly configured."; exit 1)

run-dev: check-nix check-kubernetes
	kubectl apply -f deploy/stackable-operators-ns.yaml
	nix run --extra-experimental-features "nix-command flakes" -f. tilt -- up --port 5440 --namespace stackable-operators

stop-dev: check-nix check-kubernetes
	nix run --extra-experimental-features "nix-command flakes" -f. tilt -- down
