openssl req \
    -x509 \
    -nodes \
    -subj=/$ADMIN_DN \
    -out=/stackable/tls-admin-cert/tls.crt \
    -keyout=/stackable/tls-admin-cert/tls.key

cat \
    /stackable/tls-server/ca.crt \
    /stackable/tls-admin-cert/tls.crt > \
    /stackable/tls-server-ca/ca.crt
