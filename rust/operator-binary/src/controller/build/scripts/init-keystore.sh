#!/usr/bin/env bash

set -e -u -x -o pipefail

bin/opensearch-keystore create

for i in keystore-secrets/*
do
    key=$(basename "$i")
    bin/opensearch-keystore add-file "$key" "$i"
done

cp --archive config/opensearch.keystore initialized-keystore
