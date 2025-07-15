use stackable_operator::{
    builder::pdb::PodDisruptionBudgetBuilder,
    k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector,
    kube::{Resource, api::ObjectMeta},
};

use crate::framework::{ControllerName, IsLabelValue, OperatorName, ProductName, RoleName};

pub fn pod_disruption_budget_builder_with_role(
    owner: &(impl Resource<DynamicType = ()> + IsLabelValue),
    product_name: &ProductName,
    role_name: &RoleName,
    operator_name: &OperatorName,
    controller_name: &ControllerName,
) -> PodDisruptionBudgetBuilder<ObjectMeta, LabelSelector, ()> {
    PodDisruptionBudgetBuilder::new_with_role(
        owner,
        &product_name.to_label_value(),
        &role_name.to_label_value(),
        &operator_name.to_label_value(),
        &controller_name.to_label_value(),
    )
    .expect("Labels should be created because all given parameters produce valid label values")
}
