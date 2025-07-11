use super::{ClusterName, RoleGroupName, RoleName};
use crate::framework::{HasObjectName, MAX_OBJECT_NAME_LENGTH, kvp::label::MAX_LABEL_VALUE_LENGTH};

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
    /// The result is a valid DNS subdomain name as defined in RFC 1123 that can be used e.g. as a name
    /// for a StatefulSet.
    fn qualified_role_group_name(&self) -> String {
        format!(
            "{}-{}-{}",
            self.cluster_name.to_object_name(),
            self.role_name.to_object_name(),
            self.role_group_name.to_object_name()
        )
    }

    pub fn role_group_config_map(&self) -> String {
        // Compile-time check
        const _: () = assert!(
            ResourceNames::MAX_QUALIFIED_ROLE_GROUP_NAME_LENGTH <= MAX_OBJECT_NAME_LENGTH,
            "The ConfigMap name `<cluster_name>-<role_name>-<role_group_name>` must not exceed 253 characters."
        );

        self.qualified_role_group_name()
    }

    pub fn stateful_set_name(&self) -> String {
        // Compile-time check
        const _: () = assert!(
            // see https://github.com/kubernetes/kubernetes/issues/64023
            ResourceNames::MAX_QUALIFIED_ROLE_GROUP_NAME_LENGTH
            + 1 // dash
            + 10 // digits for the controller-revision-hash label
            <= MAX_LABEL_VALUE_LENGTH,
            "The maximum lengths of the cluster name, role name and role group name must be defined so that the combination of these names (including separators and the sequential pod number or hash) is also a valid object name with a maximum of 63 characters (see RFC 1123)"
        );

        self.qualified_role_group_name()
    }

    pub fn headless_service_name(&self) -> String {
        const SUFFIX: &str = "-headless";

        // Compile-time check
        const _: () = assert!(
            ResourceNames::MAX_QUALIFIED_ROLE_GROUP_NAME_LENGTH + SUFFIX.len()
                <= MAX_LABEL_VALUE_LENGTH,
            "The Service name `<cluster_name>-<role_name>-<role_group_name>-headless` must not exceed 63 characters."
        );

        format!("{}{SUFFIX}", self.qualified_role_group_name())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{ClusterName, RoleGroupName, RoleName};
    use crate::framework::role_group_utils::ResourceNames;

    #[test]
    fn test_stateful_set_name() {
        let resource_names = ResourceNames {
            cluster_name: ClusterName::from_str("test-cluster")
                .expect("should be a valid cluster name"),
            role_name: RoleName::from_str("data-nodes").expect("should be a valid role name"),
            role_group_name: RoleGroupName::from_str("ssd-storage")
                .expect("should be a valid role group name"),
        };

        assert_eq!(
            "test-cluster-data-nodes-ssd-storage",
            resource_names.stateful_set_name()
        );
    }
}
