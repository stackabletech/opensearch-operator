use stackable_operator::{
    builder::meta::OwnerReferenceBuilder,
    k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference, kube::Resource,
};

use crate::framework::HasUid;

/// Infallible variant of `stackable_operator::builder::meta::ObjectMetaBuilder::ownerreference_from_resource`
pub fn ownerreference_from_resource(
    resource: &(impl Resource<DynamicType = ()> + HasUid),
    block_owner_deletion: Option<bool>,
    controller: Option<bool>,
) -> OwnerReference {
    OwnerReferenceBuilder::new()
        // Set api_version, kind, name and additionally the UID if it exists.
        .initialize_from_resource(resource)
        // Ensure that the UID is set.
        .uid(resource.to_uid())
        .block_owner_deletion_opt(block_owner_deletion)
        .controller_opt(controller)
        .build()
        .expect("api_version, kind, name and uid should be set")
}
