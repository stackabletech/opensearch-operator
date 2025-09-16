use std::str::FromStr;

use super::{ClusterName, ConfigMapName, ListenerName, RoleGroupName, RoleName, StatefulSetName};
use crate::framework::ServiceName;

/// Type-safe names for role-group resources
pub struct ResourceNames {
    pub cluster_name: ClusterName,
    pub role_name: RoleName,
    pub role_group_name: RoleGroupName,
}

impl ResourceNames {
    // used at compile-time
    #[allow(dead_code)]
    const MAX_QUALIFIED_ROLE_GROUP_NAME_LENGTH: usize = ClusterName::MAX_LENGTH
            + 1 // dash
            + RoleName::MAX_LENGTH
            + 1 // dash
            + RoleGroupName::MAX_LENGTH;

    /// Creates a qualified role group name consisting of the cluster name, role name and role-group
    /// name.
    ///
    /// The result is a valid DNS subdomain name as defined in RFC 1123 that can be used e.g. as a name
    /// for a [`StatefulSet`].
    ///
    /// [`StatefulSet`]: stackable_operator::k8s_openapi::api::apps::v1::StatefulSet
    fn qualified_role_group_name(&self) -> String {
        format!(
            "{}-{}-{}",
            self.cluster_name, self.role_name, self.role_group_name,
        )
    }

    pub fn role_group_config_map(&self) -> ConfigMapName {
        // Compile-time check
        const _: () = assert!(
            ResourceNames::MAX_QUALIFIED_ROLE_GROUP_NAME_LENGTH <= ConfigMapName::MAX_LENGTH,
            "The string `<cluster_name>-<role_name>-<role_group_name>` must not exceed the limit of \
            ConfigMap names."
        );

        ConfigMapName::from_str(&self.qualified_role_group_name())
            .expect("should be a valid ConfigMap name")
    }

    pub fn stateful_set_name(&self) -> StatefulSetName {
        // Compile-time check
        const _: () = assert!(
            // see https://github.com/kubernetes/kubernetes/issues/64023
            ResourceNames::MAX_QUALIFIED_ROLE_GROUP_NAME_LENGTH
            + 1 // dash
            + 10 // digits for the controller-revision-hash label
            <= StatefulSetName::MAX_LENGTH,
            "The string `<cluster_name>-<role_name>-<role_group_name>-<controller_revision_hash>` \
            must not exceed the limit of StatefulSet names."
        );

        StatefulSetName::from_str(&self.qualified_role_group_name())
            .expect("should be a valid StatefulSet name")
    }

    pub fn headless_service_name(&self) -> ServiceName {
        const SUFFIX: &str = "-headless";

        // Compile-time check
        const _: () = assert!(
            ResourceNames::MAX_QUALIFIED_ROLE_GROUP_NAME_LENGTH + SUFFIX.len()
                <= ServiceName::MAX_LENGTH,
            "The string `<cluster_name>-<role_name>-<role_group_name>-headless` must not exceed the \
            limit of Service names."
        );

        ServiceName::from_str(&format!("{}{SUFFIX}", self.qualified_role_group_name()))
            .expect("should be a valid Service name")
    }

    pub fn listener_name(&self) -> ListenerName {
        // Compile-time check
        const _: () = assert!(
            ResourceNames::MAX_QUALIFIED_ROLE_GROUP_NAME_LENGTH <= ListenerName::MAX_LENGTH,
            "The string `<cluster_name>-<role_name>-<role_group_name>` must not exceed the limit of \
            Listener names."
        );

        ListenerName::from_str(&self.qualified_role_group_name())
            .expect("should be a valid Listener name")
    }
}

#[cfg(test)]
mod tests {
    use super::{ClusterName, RoleGroupName, RoleName};
    use crate::framework::{
        ConfigMapName, ListenerName, ServiceName, StatefulSetName, role_group_utils::ResourceNames,
    };

    #[test]
    fn test_resource_names() {
        let resource_names = ResourceNames {
            cluster_name: ClusterName::from_str_unsafe("test-cluster"),
            role_name: RoleName::from_str_unsafe("data-nodes"),
            role_group_name: RoleGroupName::from_str_unsafe("ssd-storage"),
        };

        assert_eq!(
            "test-cluster-data-nodes-ssd-storage",
            resource_names.qualified_role_group_name()
        );
        assert_eq!(
            ConfigMapName::from_str_unsafe("test-cluster-data-nodes-ssd-storage"),
            resource_names.role_group_config_map()
        );
        assert_eq!(
            StatefulSetName::from_str_unsafe("test-cluster-data-nodes-ssd-storage"),
            resource_names.stateful_set_name()
        );
        assert_eq!(
            ServiceName::from_str_unsafe("test-cluster-data-nodes-ssd-storage-headless"),
            resource_names.headless_service_name()
        );
        assert_eq!(
            ListenerName::from_str_unsafe("test-cluster-data-nodes-ssd-storage"),
            resource_names.listener_name()
        );
    }
}
