use stackable_operator::{
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    k8s_openapi::api::core::v1::ObjectReference,
};

use super::{
    AppName, ControllerName, HasNamespace, HasObjectName, HasUid, IsLabelValue, OperatorName,
};
use crate::framework::kvp::label::LABEL_VALUE_MAX_LENGTH;

pub fn cluster_resources_new(
    app_name: &AppName,
    operator_name: &OperatorName,
    controller_name: &ControllerName,
    cluster: &(impl HasObjectName + HasNamespace + HasUid),
    apply_strategy: ClusterResourceApplyStrategy,
) -> ClusterResources {
    // ClusterResources::new creates a label value from the given app name by appending
    // `-operator`. For the resulting label value to be valid, it must not exceed 63 characters.
    // Check at compile time that AppName::MAX_LENGTH is defined accordingly.
    const _: () = assert!(
        AppName::MAX_LENGTH <= LABEL_VALUE_MAX_LENGTH - "-operator".len(),
        "The label value `<app_name>-operator` must not exceed 63 characters."
    );

    ClusterResources::new(
        &app_name.to_label_value(),
        &operator_name.to_label_value(),
        &controller_name.to_label_value(),
        &ObjectReference {
            name: Some(cluster.to_object_name()),
            namespace: Some(cluster.to_namespace()),
            uid: Some(cluster.to_uid()),
            ..Default::default()
        },
        apply_strategy,
    )
    .expect("")
}
