function log () {
    level="$1"
    message="$2"

    timestamp="$(date --utc +"%FT%T.%3NZ")"
    echo "$timestamp [$level] $message"
}

function info () {
    message="$@"

    log INFO "$message"
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
            "configuration, as such an admin certificate is not " \
            "required. The security configuration is managed by the " \
            "pod \"$MANAGING_POD\"."

        cp \
            /stackable/tls-server/ca.crt \
            /stackable/tls-server-ca/ca.crt
        exit 0
    fi
}

function create_admin_certificate () {
    info "Create admin certificate with \"$ADMIN_DN\""

    openssl req \
        -x509 \
        -nodes \
        -subj=/$ADMIN_DN \
        -out=/stackable/tls-admin-cert/tls.crt \
        -keyout=/stackable/tls-admin-cert/tls.key
}

function concatenate_certificates () {
    info "Add admin certificate to the trusted CAs"

    cat \
        /stackable/tls-server/ca.crt \
        /stackable/tls-admin-cert/tls.crt > \
        /stackable/tls-server-ca/ca.crt
}

check_pod
create_admin_certificate
concatenate_certificates
