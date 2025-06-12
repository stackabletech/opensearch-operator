use stackable_operator::{
    builder::pdb::PodDisruptionBudgetBuilder,
    k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector,
    kube::{Resource, api::ObjectMeta},
};

use crate::framework::{AppName, ControllerName, IsLabelValue, OperatorName, RoleName};

pub fn pod_disruption_budget_builder_with_role(
    owner: &(impl Resource<DynamicType = ()> + IsLabelValue),
    app_name: &AppName,
    role_name: &RoleName,
    operator_name: &OperatorName,
    controller_name: &ControllerName,
) -> PodDisruptionBudgetBuilder<ObjectMeta, LabelSelector, ()> {
    PodDisruptionBudgetBuilder::new_with_role(
        owner,
        &app_name.to_label_value(),
        &role_name.to_label_value(),
        &operator_name.to_label_value(),
        &controller_name.to_label_value(),
    )
    .expect("Labels should be created because all given parameters produce valid label values")
}
