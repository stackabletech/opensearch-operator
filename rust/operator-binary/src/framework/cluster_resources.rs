use stackable_operator::{
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    k8s_openapi::api::core::v1::ObjectReference,
};

use super::{
    ControllerName, HasNamespace, HasObjectName, HasUid, IsLabelValue, OperatorName, ProductName,
};
use crate::framework::kvp::label::LABEL_VALUE_MAX_LENGTH;

pub fn cluster_resources_new(
    product_name: &ProductName,
    operator_name: &OperatorName,
    controller_name: &ControllerName,
    cluster: &(impl HasObjectName + HasNamespace + HasUid),
    apply_strategy: ClusterResourceApplyStrategy,
) -> ClusterResources {
    // ClusterResources::new creates a label value from the given app name by appending
    // `-operator`. For the resulting label value to be valid, it must not exceed 63 characters.
    // Check at compile time that ProductName::MAX_LENGTH is defined accordingly.
    const _: () = assert!(
        ProductName::MAX_LENGTH <= LABEL_VALUE_MAX_LENGTH - "-operator".len(),
        "The label value `<product_name>-operator` must not exceed 63 characters."
    );

    ClusterResources::new(
        &product_name.to_label_value(),
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
