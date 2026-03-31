#!/usr/bin/env bash
#
# Expected environment variables:
# - OPENSEARCH_PATH_CONF
# - POD_NAME
# - MANAGE_ACTIONGROUPS
# - MANAGE_ALLOWLIST
# - MANAGE_AUDIT
# - MANAGE_CONFIG
# - MANAGE_INTERNALUSERS
# - MANAGE_NODESDN
# - MANAGE_ROLES
# - MANAGE_ROLESMAPPING
# - MANAGE_TENANTS

# TODO config_files vs. configuration_files

set -u -o pipefail

VECTOR_CONTROL_DIR=/stackable/log/_vector
SECURITY_CONFIG_DIR="$OPENSEARCH_PATH_CONF/opensearch-security"

declare -a CONFIG_FILETYPES=(
    actiongroups
    allowlist
    audit
    config
    internalusers
    nodesdn
    roles
    rolesmapping
    tenants
)

declare -A CONFIG_FILENAME=(
    [actiongroups]=action_groups.yml
    [allowlist]=allowlist.yml
    [audit]=audit.yml
    [config]=config.yml
    [internalusers]=internal_users.yml
    [nodesdn]=nodes_dn.yml
    [roles]=roles.yml
    [rolesmapping]=roles_mapping.yml
    [tenants]=tenants.yml
)

declare -a managed_filetypes

last_applied_config_hashes=""

function log () {
    level="$1"
    message="$2"

    timestamp="$(date --utc +"%FT%T.%3NZ")"
    echo "$timestamp [$level] $message"
}

function debug () {
    message="$*"

    log DEBUG "$message"
}

function info () {
    message="$*"

    log INFO "$message"
}

function warn () {
    message="$1"

    log WARN "$message"
}

function config_file () {
    filetype="$1"

    echo "$SECURITY_CONFIG_DIR/${CONFIG_FILENAME[$filetype]}"
}

function symlink_config_files () {
    for filetype in "${CONFIG_FILETYPES[@]}"
    do
        ln --force --symbolic \
            "$SECURITY_CONFIG_DIR/$filetype/${CONFIG_FILENAME[$filetype]}" \
            "$(config_file "$filetype")"
    done
}

function initialize_managed_configuration_filetypes () {
    for filetype in "${CONFIG_FILETYPES[@]}"
    do
        envvar="MANAGE_${filetype^^}"
        if test "${!envvar}" = "true"
        then
            info "Watch managed configuration type \"$filetype\"."

            managed_filetypes+=("$filetype")
        else
            info "Skip unmanaged configuration type \"$filetype\"."
        fi
    done
}

function calculate_config_hashes () {
    for filetype in "${managed_filetypes[@]}"
    do
        file=$(config_file "$filetype")
        sha256sum "$file"
    done
}

function wait_seconds_or_shutdown () {
    seconds="$1"

    debug "Wait for $seconds seconds..."

    if test ! -e "$VECTOR_CONTROL_DIR/shutdown"
    then
        inotifywait \
            --quiet --quiet \
            --timeout "$seconds" \
            --event create \
            "$VECTOR_CONTROL_DIR"
    fi

    # Only the file named "shutdown" should be created in
    # VECTOR_CONTROL_DIR. If another file is created instead, this
    # function will return early; this is acceptable and has no adverse
    # effects.
    if test -e "$VECTOR_CONTROL_DIR/shutdown"
    then
        info "Shut down"
        exit 0
    fi
}

function wait_for_configuration_changes_or_shutdown () {
    info "Wait for security configuration changes..."

    while test "$(calculate_config_hashes)" = "$last_applied_config_hashes"
    do
        wait_seconds_or_shutdown 10
    done

    info "Configuration change detected"
}

function wait_for_shutdown () {
    until test ! -e "$VECTOR_CONTROL_DIR/shutdown"
    do
        inotifywait \
            --quiet --quiet \
            --event create \
            "$VECTOR_CONTROL_DIR"
    done

    info "Shut down"
    exit 0
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

        wait_for_shutdown
    fi
}

function initialize_security_index() {
    info "Initialize the security index."

    last_applied_config_hashes=$(calculate_config_hashes)

    until plugins/opensearch-security/tools/securityadmin.sh \
        --configdir "$SECURITY_CONFIG_DIR" \
        --disable-host-name-verification \
        -cacert "$OPENSEARCH_PATH_CONF/tls/ca.crt" \
        -cert "$OPENSEARCH_PATH_CONF/tls/tls.crt" \
        -key "$OPENSEARCH_PATH_CONF/tls/tls.key"
    do
        warn "Initializing the security index failed."
        wait_seconds_or_shutdown 10
    done
}

function update_config () {
    last_applied_config_hashes=$(calculate_config_hashes)

    for filetype in "${managed_filetypes[@]}"
    do
        file=$(config_file "$filetype")

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
            wait_seconds_or_shutdown 10
        done
    done
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

        update_config
    elif test "$STATUS_CODE" = "404"
    then
        initialize_security_index
    else
        warn "Checking the security index failed."
        wait_seconds_or_shutdown 10
        update_security_index
    fi
}

# Ensure that VECTOR_CONTROL_DIR exists, so that calls to inotifywait do not
# fail.
mkdir --parents "$VECTOR_CONTROL_DIR"

check_pod
symlink_config_files
initialize_managed_configuration_filetypes

while true
do
    update_security_index
    wait_for_configuration_changes_or_shutdown
done
