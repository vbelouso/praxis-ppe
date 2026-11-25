//! Live Keycloak coverage for JWT bearer subject import and token exchange.

#![cfg(all(feature = "oauth", feature = "http-hyper"))]
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "live integration test"
)]

use std::sync::Arc;

use praxis_policy::http_hyper::HyperTransport;
use praxis_policy::{OAUTH_KIND, OAuthDelegatorFactory};
use praxis_policy_core::config::PolicyConfig;
use praxis_policy_core::delegation::{DelegationPayload, HOOK_TOKEN_DELEGATE, TokenDelegateHook};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::raw_credentials::{
    Credential, RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
};
use praxis_policy_core::extensions::security::{SecurityExtension, SubjectExtension};
use praxis_policy_core::factory::PluginFactoryRegistry;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};
use serde_json::json;

/// Required environment:
///
/// - PPE_IMPORT_LIVE_TOKEN_ENDPOINT
/// - PPE_IMPORT_LIVE_CLIENT_ID
/// - PPE_IMPORT_LIVE_CLIENT_SECRET
/// - PPE_IMPORT_LIVE_AUDIENCE
/// - PPE_IMPORT_LIVE_EXTERNAL_JWT
/// - PPE_IMPORT_LIVE_DOWNSTREAM_AUDIENCE
///
/// The Keycloak realms must already be configured with the JWT Authorization
/// Grant provider, allowed audience, confidential client, and federated
/// identity link described in the design.
#[tokio::test]
#[ignore = "requires a preconfigured live Keycloak"]
async fn live_keycloak_imports_external_jwt_and_exchanges_it() {
    let token_endpoint = std::env::var("PPE_IMPORT_LIVE_TOKEN_ENDPOINT").unwrap();
    let client_id = std::env::var("PPE_IMPORT_LIVE_CLIENT_ID").unwrap();
    let client_secret = std::env::var("PPE_IMPORT_LIVE_CLIENT_SECRET").unwrap();
    let audience = std::env::var("PPE_IMPORT_LIVE_AUDIENCE").unwrap();
    let external_jwt = std::env::var("PPE_IMPORT_LIVE_EXTERNAL_JWT").unwrap();
    let downstream_audience = std::env::var("PPE_IMPORT_LIVE_DOWNSTREAM_AUDIENCE").unwrap();

    let config = PluginConfig {
        name: "live-keycloak-import".into(),
        kind: OAUTH_KIND.to_owned(),
        hooks: vec![HOOK_TOKEN_DELEGATE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: [
            "perform_http".to_owned(),
            "read_inbound_credentials".to_owned(),
            "read_subject".to_owned(),
        ]
        .into(),
        config: Some(json!({
            "token_endpoint": token_endpoint,
            "client_id": client_id,
            "client_secret_source": {
                "kind": "literal",
                "secret": client_secret
            },
            "insecure_http": false,
            "subject_import": {
                "kind": "jwt_bearer",
                "authorization_server_audience": audience
            }
        })),
        ..Default::default()
    };

    let mut factories = PluginFactoryRegistry::new();
    factories.register(OAUTH_KIND, Box::new(OAuthDelegatorFactory));
    let policy_config = PolicyConfig {
        plugins: vec![config],
        ..Default::default()
    };
    let engine = Arc::new(
        PolicyEngine::from_config(policy_config, &factories)
            .expect("live Keycloak plugin config constructs"),
    );
    engine.set_http_transport(Arc::new(
        HyperTransport::new().with_allow_private_destinations(),
    ));
    engine.initialize().await.unwrap();

    let payload = DelegationPayload::new(external_jwt.clone(), "live-downstream")
        .with_target_audience(downstream_audience)
        .with_required_permissions(vec!["read".to_owned()]);

    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new(
            external_jwt,
            Credential::Header {
                name: "Authorization".into(),
            },
            TokenKind::Jwt,
        ),
    );
    let mut security = SecurityExtension::default();
    let mut subject = SubjectExtension::default();
    subject.id = Some("live-external-subject".into());
    security.subject = Some(subject);
    let mut extensions = Extensions::default();
    extensions.raw_credentials = Some(Arc::new(raw));
    extensions.security = Some(Arc::new(security));

    let (result, _background) = engine
        .invoke_named::<TokenDelegateHook>(HOOK_TOKEN_DELEGATE, payload, extensions, None)
        .await;
    assert!(
        result.continue_processing,
        "live Keycloak import failed: {:?}",
        result.violation
    );
    assert!(
        result.payload_modified,
        "live Keycloak import did not modify the delegation payload"
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("live Keycloak import should return a delegation payload");
    let delegated_token = final_payload
        .delegated_token
        .as_ref()
        .expect("live Keycloak import should return a delegated token");
    assert!(
        !delegated_token.token.is_empty(),
        "live Keycloak import returned an empty delegated token"
    );
}
