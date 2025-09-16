use stackable_operator::{
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    k8s_openapi::api::core::v1::ObjectReference,
};

use super::{ClusterName, ControllerName, NamespaceName, OperatorName, ProductName, Uid};
use crate::framework::{MAX_LABEL_VALUE_LENGTH, NameIsValidLabelValue};

/// Infallible variant of [`stackable_operator::cluster_resources::ClusterResources::new`]
pub fn cluster_resources_new(
    product_name: &ProductName,
    operator_name: &OperatorName,
    controller_name: &ControllerName,
    cluster_name: &ClusterName,
    cluster_namespace: &NamespaceName,
    cluster_uid: &Uid,
    apply_strategy: ClusterResourceApplyStrategy,
) -> ClusterResources {
    // Compile-time check
    // ClusterResources::new creates a label value from the given app name by appending
    // `-operator`. For the resulting label value to be valid, it must not exceed
    // MAX_LABEL_VALUE_LENGTH.
    const _: () = assert!(
        ProductName::MAX_LENGTH + "-operator".len() <= MAX_LABEL_VALUE_LENGTH,
        "The string `<cluster_name>-operator` must not exceed the limit of Label names."
    );

    ClusterResources::new(
        &product_name.to_label_value(),
        &operator_name.to_label_value(),
        &controller_name.to_label_value(),
        &ObjectReference {
            name: Some(cluster_name.to_string()),
            namespace: Some(cluster_namespace.to_string()),
            uid: Some(cluster_uid.to_string()),
            ..Default::default()
        },
        apply_strategy,
    )
    .expect("ClusterResources should be created because the cluster object reference contains name, namespace and uid.")
}
