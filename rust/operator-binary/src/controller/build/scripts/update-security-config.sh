#!/usr/bin/env bash

set -u -o pipefail

function log () {
    level="$1"
    message="$2"

    timestamp="$(date --utc +"%FT%T.%3NZ")"
    echo "$timestamp [$level] $message"
}

function info () {
    message="$*"

    log INFO "$message"
}

function warn () {
    message="$1"

    log WARN "$message"
}

function wait_seconds () {
    seconds="$1"

    if test "$seconds" = 0
    then
        info "Wait until pod is restarted..."
    else
        info "Wait for $seconds seconds..."
    fi

    if test ! -e /stackable/log/_vector/shutdown
    then
        mkdir --parents /stackable/log/_vector
        inotifywait \
            --quiet --quiet \
            --timeout "$seconds" \
            --event create \
            /stackable/log/_vector
    fi

    if test -e /stackable/log/_vector/shutdown
    then
        info "Shut down"
        exit 0
    fi
}

function check_pod () {
    POD_INDEX="${POD_NAME##*-}"

    if test "$POD_INDEX" = "0"
    then
        info "This pod is responsible for managing the security" \
            "configuration."
    else
        MANAGING_POD="${POD_NAME%-*}-0"
        info "This pod is not responsible for managing the security" \
            "configuration. The security configuration is managed by" \
            "the pod \"$MANAGING_POD\"."

        wait_seconds 0
    fi
}

function initialize_security_index() {
    info "Initialize the security index."

    until plugins/opensearch-security/tools/securityadmin.sh \
        --configdir "$OPENSEARCH_PATH_CONF/opensearch-security" \
        --disable-host-name-verification \
        -cacert "$OPENSEARCH_PATH_CONF/tls/ca.crt" \
        -cert "$OPENSEARCH_PATH_CONF/tls/tls.crt" \
        -key "$OPENSEARCH_PATH_CONF/tls/tls.key"
    do
        warn "Initializing the security index failed."
        wait_seconds 10
    done
}

function update_config () {
    filetype="$1"
    filename="$2"

    file="$OPENSEARCH_PATH_CONF/opensearch-security/$filename"

    envvar="MANAGE_${filetype^^}"
    if test "${!envvar}" = "true"
    then
        info "Update managed configuration type \"$filetype\"."

        until plugins/opensearch-security/tools/securityadmin.sh \
            --type "$filetype" \
            --file "$file" \
            --disable-host-name-verification \
            -cacert "$OPENSEARCH_PATH_CONF/tls/ca.crt" \
            -cert "$OPENSEARCH_PATH_CONF/tls/tls.crt" \
            -key "$OPENSEARCH_PATH_CONF/tls/tls.key"
        do
            warn "Updating \"$filetype\" in the security index failed."
            wait_seconds 10
        done
    else
        info "Skip unmanaged configuration type \"$filetype\"."
    fi
}

function update_security_index() {
    info "Check the status of the security index."

    STATUS_CODE=$(curl \
        --insecure \
        --cert "$OPENSEARCH_PATH_CONF/tls/tls.crt" \
        --key "$OPENSEARCH_PATH_CONF/tls/tls.key" \
        --silent \
        --output /dev/null \
        --write-out "%{http_code}" \
        https://localhost:9200/.opendistro_security)
    if test "$STATUS_CODE" = "200"
    then
        info "The security index is already initialized."

        update_config actiongroups action_groups.yml
        update_config allowlist allowlist.yml
        update_config audit audit.yml
        update_config config config.yml
        update_config internalusers internal_users.yml
        update_config nodesdn nodes_dn.yml
        update_config roles roles.yml
        update_config rolesmapping roles_mapping.yml
        update_config tenants tenants.yml
    elif test "$STATUS_CODE" = "404"
    then
        initialize_security_index
    else
        warn "Checking the security index failed."
        wait_seconds 10
        check_security_index
    fi
}

check_pod

update_security_index

info "Wait for security configuration changes..."
# Wait until the pod is restarted due to a change of the Secret.
wait_seconds 0
