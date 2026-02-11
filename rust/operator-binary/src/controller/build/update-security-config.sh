function wait_seconds () {
    seconds="$1"

    if test "$seconds" = 0
    then
        echo "Wait until pod is restarted..."
    else
        echo "Wait for $seconds seconds..."
    fi

    if test ! -e /stackable/log/_vector/shutdown
    then
        mkdir --parents /stackable/log/_vector
        inotifywait \
            --quiet --quiet \
            --timeout $seconds \
            --event create \
            /stackable/log/_vector
    fi

    if test -e /stackable/log/_vector/shutdown
    then
        echo "Shut down"
        exit 0
    fi
}

function initialize_security_index() {
    echo "Initialize the security index."

    until plugins/opensearch-security/tools/securityadmin.sh \
        --configdir "$OPENSEARCH_PATH_CONF/opensearch-security" \
        --disable-host-name-verification \
        -cacert "$OPENSEARCH_PATH_CONF/tls/ca.crt" \
        -cert "$OPENSEARCH_PATH_CONF/tls/tls.crt" \
        -key "$OPENSEARCH_PATH_CONF/tls/tls.key"
    do
        echo "Initializing the security index failed."
        wait_seconds 10
    done
}

function check_security_index() {
    echo "Check the status of the security index."

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
        echo "The security index is already initialized."
    elif test "$STATUS_CODE" = "404"
    then
        initialize_security_index
    else
        echo "Checking the security index failed."
        wait_seconds 10
        check_security_index
    fi
}

function update_config () {
    filetype="$1"
    filename="$2"

    file="$OPENSEARCH_PATH_CONF/opensearch-security/$filename"

    envvar="MANAGE_${filetype^^}"
    if test "${!envvar}" = "true"
    then
        echo "Update managed configuration type \"$filetype\"."

        until plugins/opensearch-security/tools/securityadmin.sh \
            --type "$filetype" \
            --file "$file" \
            --disable-host-name-verification \
            -cacert "$OPENSEARCH_PATH_CONF/tls/ca.crt" \
            -cert "$OPENSEARCH_PATH_CONF/tls/tls.crt" \
            -key "$OPENSEARCH_PATH_CONF/tls/tls.key"
        do
            echo "Updating \"$filetype\" in the security index failed."
            wait_seconds 10
        done
    else
        echo "Skip unmanaged configuration type \"$filetype\"."
    fi
}

check_security_index

update_config actiongroups action_groups.yml
update_config allowlist allowlist.yml
update_config audit audit.yml
update_config config config.yml
update_config internalusers internal_users.yml
update_config nodesdn nodes_dn.yml
update_config roles roles.yml
update_config rolesmapping roles_mapping.yml
update_config tenants tenants.yml

echo "Wait for security configuration changes..."
# Wait until the pod is restarted due to a change of the Secret.
wait_seconds 0
