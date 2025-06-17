use stackable_operator::{
    kube::Resource,
    kvp::{Labels, ObjectLabels},
};

use crate::framework::{
    ControllerName, IsLabelValue, OperatorName, ProductName, ProductVersion, RoleGroupName,
    RoleName,
};

pub const LABEL_VALUE_MAX_LENGTH: usize = 63;

pub fn recommended_labels(
    owner: &(impl Resource + IsLabelValue),
    product_name: &ProductName,
    product_version: &ProductVersion,
    operator_name: &OperatorName,
    controller_name: &ControllerName,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    let object_labels = ObjectLabels {
        owner,
        app_name: &product_name.to_label_value(),
        app_version: &product_version.to_label_value(),
        operator_name: &operator_name.to_label_value(),
        controller_name: &controller_name.to_label_value(),
        role: &role_name.to_label_value(),
        role_group: &role_group_name.to_label_value(),
    };
    Labels::recommended(object_labels)
        .expect("Labels should be created because all given parameters produce valid label values")
}

pub fn role_group_selector(
    owner: &(impl Resource + IsLabelValue),
    product_name: &ProductName,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    Labels::role_group_selector(
        owner,
        &product_name.to_label_value(),
        &role_name.to_label_value(),
        &role_group_name.to_label_value(),
    )
    .expect("Labels should be created because all given parameters produce valid label values")
}
