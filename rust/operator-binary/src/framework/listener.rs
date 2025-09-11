use stackable_operator::{
    builder::pod::volume::{ListenerOperatorVolumeSourceBuilder, ListenerReference},
    k8s_openapi::api::core::v1::PersistentVolumeClaim,
    kvp::Labels,
};

use super::PersistentVolumeClaimName;

// TODO Listener name vs. class?
// String is bad!

/// Infallible variant of `ListenerOperatorVolumeSourceBuilder::build_pvc`
pub fn listener_pvc(
    listener_name: String,
    labels: &Labels,
    pvc_name: &PersistentVolumeClaimName,
) -> PersistentVolumeClaim {
    ListenerOperatorVolumeSourceBuilder::new(
        &ListenerReference::ListenerName(listener_name),
        labels,
    )
    .expect("should return Ok independent of the given parameters")
    .build_pvc(pvc_name.to_string())
    .expect(
        "should return a PersistentVolumeClaim, because the only check is that \
        listener_group_name is a valid annotation value and there are no restrictions on single \
        annotation values",
    )
}
