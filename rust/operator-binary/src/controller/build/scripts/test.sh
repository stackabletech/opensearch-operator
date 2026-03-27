#!/usr/bin/env sh

OPENSEARCH_PATH_CONF="$(pwd)/test-config" \
    POD_NAME="security-config-0" \
    MANAGE_ACTIONGROUPS="true" \
    MANAGE_ALLOWLIST="true" \
    MANAGE_AUDIT="false" \
    MANAGE_CONFIG="true" \
    MANAGE_INTERNALUSERS="true" \
    MANAGE_NODESDN="false" \
    MANAGE_ROLES="true" \
    MANAGE_ROLESMAPPING="true" \
    MANAGE_TENANTS="true" \
    sh ./update-security-config.sh
