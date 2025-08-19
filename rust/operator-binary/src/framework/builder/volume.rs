use stackable_operator::{
    builder::pod::volume::{SecretFormat, SecretOperatorVolumeSourceBuilder, VolumeBuilder},
    k8s_openapi::api::core::v1::Volume,
    time::Duration,
};

pub fn build_tls_volume(
    volume_name: &str,
    tls_secret_class_name: &str,
    service_scopes: impl IntoIterator<Item = impl AsRef<str>>,
    secret_format: SecretFormat,
    requested_secret_lifetime: &Duration,
    listener_scope: Option<&str>,
) -> Volume {
    let mut secret_volume_source_builder =
        SecretOperatorVolumeSourceBuilder::new(tls_secret_class_name);

    for scope in service_scopes {
        secret_volume_source_builder.with_service_scope(scope.as_ref());
    }
    if let Some(listener_scope) = listener_scope {
        secret_volume_source_builder.with_listener_volume_scope(listener_scope);
    }

    VolumeBuilder::new(volume_name)
        .ephemeral(
            secret_volume_source_builder
                .with_pod_scope()
                .with_format(secret_format)
                .with_auto_tls_cert_lifetime(*requested_secret_lifetime)
                .build()
                .expect("volume should be built without parse errors"),
        )
        .build()
}
