use stackable_operator::{
    builder::pod::volume::{ListenerOperatorVolumeSourceBuilder, ListenerReference},
    k8s_openapi::api::core::v1::PersistentVolumeClaim,
    kvp::Labels,
};

pub fn listener_pvc(
    listener_group_name: String,
    labels: &Labels,
    pvc_name: String,
) -> PersistentVolumeClaim {
    ListenerOperatorVolumeSourceBuilder::new(
        &ListenerReference::ListenerName(listener_group_name),
        labels,
    )
    .build_pvc(pvc_name.to_string())
    .expect("should be a valid annotation")
}
