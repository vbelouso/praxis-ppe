# External-to-Internal JWT Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional RFC 7523 JWT Authorization Grant leg that converts an inbound external user or client JWT into an internal access token before the existing RFC 8693 token exchange.

**Architecture:** Keep identity resolution, policy, `DelegationPayload`, final token exchange, delegated-token caching, and downstream injection unchanged. Add an optional `subject_import` configuration to `delegator/oauth`, deny ineligible imports before delegated-token cache lookup, mint an internal bearer token with a dedicated RFC 7523 request/response path, and use that token as the RFC 8693 `subject_token`. Encode import mode in the delegated-token cache domain and suppress only the external-identity fallback during final subject validation.

**Tech Stack:** Rust 2024, serde/serde_json, Praxis Policy Engine plugin and extension APIs, existing `FakeTransport` OAuth integration tests, optional live Keycloak interoperability test.

**Spec:** `/home/vbelouso/repo/projects/praxis/praxis-ppe/docs/superpowers/specs/2026-11-25-external-to-internal-jwt-bridge-design.md`

## Global Constraints

- Version one supports only `subject_import.kind: jwt_bearer`.
- Version one supports only `subject: user` and `subject: client`.
- Reject `subject_import` with `subject: caller_workload` and `subject: this_workload`.
- Require a non-empty explicit `authorization_server_audience`.
- Do not configure or send import-leg `scope`.
- Leg one sends only `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion=<external JWT>`, and the existing OAuth client authentication.
- Leg one must not send `subject_token`, `subject_token_type`, `actor_token`, `actor_token_type`, `client_assertion`, or `client_assertion_type`.
- Leg two sends the internal access token as `subject_token` with `subject_token_type=urn:ietf:params:oauth:token-type:access_token`.
- Actor, target audience, and route scopes appear only on leg two.
- Import eligibility must run before delegated-token cache lookup.
- Require the selected raw credential to be `TokenKind::Jwt` and exactly equal `DelegationPayload.bearer_token`.
- Require the selected user/client identity to exist and have no `KeyBinding`.
- Require the JWT `aud` claim to identify the configured import audience; version one uses the strict Keycloak-compatible profile and accepts exactly one audience value in total.
- Reject any non-null `cnf` claim before any network call.
- Parse import responses with a dedicated type requiring non-empty `access_token` and `token_type`; accept only case-insensitive `Bearer`.
- Do not cache the internal base token.
- Encode subject-import mode in the delegated-token cache-key domain.
- Preserve `undelivered_only` retry semantics.
- Record import and exchange as separate mint effects with distinct leg labels.
- Never echo OAuth error bodies, submitted assertions, or client secrets into violation details.
- Do not modify Praxis Core.
- Do not weaken inbound JWT audience validation.

---

### Task 1: Configuration Model

**Files:**
- Modify: `crates/builtins/src/plugins/delegator_oauth/config.rs`
- Modify: `crates/builtins/src/plugins/delegator_oauth/mod.rs`
- Modify: `crates/builtins/src/plugins/delegator_oauth/delegator.rs`
- Test: `crates/builtins/src/plugins/delegator_oauth/config.rs`

**Interfaces:**
- Consumes: existing `OAuthDelegatorConfig` deserialization.
- Produces: `pub enum SubjectImportConfig` with variant `JwtBearer { authorization_server_audience: String }`, and `OAuthDelegatorConfig.subject_import: Option<SubjectImportConfig>`.

- [ ] **Step 1: Write failing configuration tests**

Add these tests to the existing `mod tests` in `config.rs`:

```rust
#[test]
fn subject_import_deserializes_jwt_bearer() {
    let raw = json!({
        "token_endpoint": "https://auth.example.com/oauth/token",
        "client_id": "gateway",
        "client_secret_source": { "kind": "literal", "secret": "dev-only" },
        "subject_import": {
            "kind": "jwt_bearer",
            "authorization_server_audience":
                "https://internal-idp.example.com/realms/internal"
        }
    });
    let cfg: OAuthDelegatorConfig = serde_json::from_value(raw).unwrap();
    match cfg.subject_import {
        Some(SubjectImportConfig::JwtBearer {
            authorization_server_audience,
        }) => assert_eq!(
            authorization_server_audience,
            "https://internal-idp.example.com/realms/internal"
        ),
        other => panic!("expected JwtBearer, got {other:?}"),
    }
}

#[test]
fn subject_import_rejects_unknown_kind() {
    let raw = json!({
        "token_endpoint": "https://auth.example.com/oauth/token",
        "client_id": "gateway",
        "client_secret_source": { "kind": "literal", "secret": "dev-only" },
        "subject_import": {
            "kind": "subject_issuer",
            "authorization_server_audience": "internal"
        }
    });
    let error = serde_json::from_value::<OAuthDelegatorConfig>(raw)
        .expect_err("unknown import kinds must fail deserialization");
    assert!(error.to_string().contains("unknown variant"));
}

#[test]
fn subject_import_requires_authorization_server_audience() {
    let raw = json!({
        "token_endpoint": "https://auth.example.com/oauth/token",
        "client_id": "gateway",
        "client_secret_source": { "kind": "literal", "secret": "dev-only" },
        "subject_import": { "kind": "jwt_bearer" }
    });
    let error = serde_json::from_value::<OAuthDelegatorConfig>(raw)
        .expect_err("authorization_server_audience is required");
    assert!(error.to_string().contains("authorization_server_audience"));
}
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
cargo test -p praxis-policy-builtins delegator_oauth::config::tests::subject_import
```

Expected: compilation fails because `SubjectImportConfig` and `subject_import` do not exist.

- [ ] **Step 3: Implement the configuration model**

Add this type above `OAuthDelegatorConfig`:

```rust
/// Optional conversion of an inbound external credential into an internal
/// credential before RFC 8693 token exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubjectImportConfig {
    /// Present the selected inbound JWT as an RFC 7523 authorization grant.
    JwtBearer {
        /// The single audience that must identify the internal authorization
        /// server. This is deliberately explicit; PPE never infers it from
        /// the token endpoint URL.
        authorization_server_audience: String,
    },
}
```

Add this field to `OAuthDelegatorConfig` after `subject_token_type`:

```rust
/// Optional first leg that imports an external user/client credential into
/// the internal authorization server before the downstream exchange.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub subject_import: Option<SubjectImportConfig>,
```

Update the public re-export in `mod.rs`:

```rust
pub use config::{ClientSecretSource, OAuthDelegatorConfig, SubjectImportConfig};
```

- [ ] **Step 4: Add construction-time audience validation**

In `OAuthDelegator::new` in `delegator.rs`, immediately after the `client_id` validation, add:

```rust
if let Some(SubjectImportConfig::JwtBearer {
    authorization_server_audience,
}) = typed.subject_import.as_ref()
{
    if authorization_server_audience.trim().is_empty() {
        return Err(Box::new(PluginError::Config {
            message: format!(
                "plugin '{}' ({KIND}): subject_import.authorization_server_audience must be non-empty",
                cfg.name
            ),
        }));
    }
}
```

Subject-mode compatibility is request-time validation, not construction-time validation, because `subject` is selected by each `DelegationPayload`.

- [ ] **Step 5: Run focused tests and verify they pass**

Run:

```bash
cargo test -p praxis-policy-builtins delegator_oauth::config::tests::subject_import
```

Expected: all three focused tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/builtins/src/plugins/delegator_oauth/config.rs crates/builtins/src/plugins/delegator_oauth/mod.rs crates/builtins/src/plugins/delegator_oauth/delegator.rs
git commit -m "feat: add oauth subject import configuration"
```

### Task 2: Pre-Cache Import Eligibility

**Files:**
- Modify: `crates/builtins/src/plugins/delegator_oauth/delegator.rs`
- Test: `crates/builtins/tests/oauth/oauth_e2e.rs`

**Interfaces:**
- Consumes: `SubjectImportConfig`, `DelegationPayload`, `Extensions`, `RawCredentialsExtension`, `SecurityExtension`.
- Produces: private `OAuthDelegator::validate_subject_import(&self, payload: &DelegationPayload, ext: &Extensions) -> Result<(), PluginViolation>`, invoked before `cache_for`.

- [ ] **Step 1: Add test fixtures for imported credentials**

In `oauth_e2e.rs`, extend imports with:

```rust
use praxis_policy_core::extensions::raw_credentials::{
    Credential, RawCredentialsExtension, RawInboundToken, TokenKind,
};
use praxis_policy_core::extensions::security::{
    ClientExtension, KeyBinding, SecurityExtension, SubjectExtension,
};
use serde_json::Value;
```

Add these helpers near the existing fixtures:

```rust
const IMPORT_AUDIENCE: &str = "https://internal-idp.example.com/realms/internal";

fn jwt_with_claims(claims: Value) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(claims.to_string());
    format!("header.{encoded}.signature")
}

fn external_user_jwt(aud: Value, cnf: Option<Value>) -> String {
    let mut claims = json!({
        "iss": "https://external-idp.example.com",
        "sub": "external-alice",
        "aud": aud,
        "jti": "import-test-001",
        "exp": 4102444800,
    });
    if let Some(cnf) = cnf {
        claims["cnf"] = cnf;
    }
    jwt_with_claims(claims)
}

fn imported_user_extensions(
    jwt: &str,
    key_binding: Option<KeyBinding>,
) -> Extensions {
    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new(
            jwt,
            Credential::Header { name: "Authorization".into() },
            TokenKind::Jwt,
        ),
    );

    let mut security = SecurityExtension::default();
    let mut subject = SubjectExtension::default();
    subject.id = Some("external-alice".into());
    subject.key_binding = key_binding;
    security.subject = Some(subject);

    let mut extensions = Extensions::default();
    extensions.raw_credentials = Some(Arc::new(raw));
    extensions.security = Some(Arc::new(security));
    extensions
}

async fn build_import_manager(http: &Arc<FakeTransport>) -> Arc<PolicyEngine> {
    let mut cfg = plugin_config(&token_endpoint());
    cfg.config.as_mut().expect("delegator config")["subject_import"] = json!({
        "kind": "jwt_bearer",
        "authorization_server_audience": IMPORT_AUDIENCE,
    });
    cfg.capabilities = [
        "perform_http".to_owned(),
        "read_inbound_credentials".to_owned(),
        "read_subject".to_owned(),
        "read_client".to_owned(),
    ]
    .into();

    let delegator = OAuthDelegator::new(cfg.clone()).expect("delegator constructs");
    let mgr = Arc::new(PolicyEngine::default());
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        Arc::new(delegator),
        cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();
    mgr.set_http_transport(http.clone());
    mgr.initialize().await.unwrap();
    mgr
}

async fn invoke_with_extensions(
    mgr: &Arc<PolicyEngine>,
    payload: DelegationPayload,
    extensions: Extensions,
) -> praxis_policy_core::executor::PipelineResult {
    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            extensions,
            None,
        )
        .await;
    result
}
```

If the crate already re-exports these extension types from
`praxis_policy_core::extensions`, import them from that shorter path and keep the
type names identical.

- [ ] **Step 2: Write failing eligibility tests**

Add a parameterized-style set of tests:

```rust
async fn assert_import_denied_before_network(
    jwt: String,
    extensions: Extensions,
    expected_reason_fragment: &str,
) {
    let http = idp(200, &json!({
        "access_token": "internal-token",
        "token_type": "Bearer"
    }).to_string());
    let mgr = build_import_manager(&http).await;
    let payload = build_payload_with_bearer(
        &jwt,
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

    let result = invoke_with_extensions(&mgr, payload, extensions).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("import must deny");
    assert_eq!(violation.code, "delegation.bad_request");
    assert!(violation.reason.contains(expected_reason_fragment));
    assert_eq!(http.call_count_for(TOKEN_PATH), 0);
}

#[tokio::test]
async fn missing_selected_raw_credential_denies_before_network() {
    let jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    assert_import_denied_before_network(
        jwt,
        Extensions::default(),
        "selected inbound credential",
    )
    .await;
}

#[tokio::test]
async fn opaque_selected_credential_denies_before_network() {
    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new(
            "opaque-token",
            Credential::Header { name: "Authorization".into() },
            TokenKind::Opaque,
        ),
    );
    let mut extensions = Extensions::default();
    extensions.raw_credentials = Some(Arc::new(raw));
    assert_import_denied_before_network(
        "opaque-token".into(),
        extensions,
        "TokenKind::Jwt",
    )
    .await;
}

#[tokio::test]
async fn key_bound_identity_denies_before_network() {
    let jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let binding = KeyBinding {
        method: "dpop".into(),
        thumbprint: "thumbprint".into(),
    };
    assert_import_denied_before_network(
        jwt.clone(),
        imported_user_extensions(&jwt, Some(binding)),
        "key-bound",
    )
    .await;
}

#[tokio::test]
async fn confirmation_claim_denies_before_network_even_without_key_binding() {
    let jwt = external_user_jwt(
        json!(IMPORT_AUDIENCE),
        Some(json!({ "jkt": "thumbprint" })),
    );
    assert_import_denied_before_network(
        jwt.clone(),
        imported_user_extensions(&jwt, None),
        "cnf",
    )
    .await;
}

#[tokio::test]
async fn credential_mismatch_denies_before_network() {
    let jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let mut payload_extensions = imported_user_extensions(&jwt, None);
    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new(
            "different-jwt",
            Credential::Header { name: "Authorization".into() },
            TokenKind::Jwt,
        ),
    );
    payload_extensions.raw_credentials = Some(Arc::new(raw));
    assert_import_denied_before_network(
        "different-jwt".into(),
        payload_extensions,
        "same credential",
    )
    .await;
}

#[tokio::test]
async fn wrong_import_audience_denies_before_network() {
    let jwt = external_user_jwt(json!("https://other-as.example.com"), None);
    assert_import_denied_before_network(
        jwt.clone(),
        imported_user_extensions(&jwt, None),
        "authorization_server_audience",
    )
    .await;
}

#[tokio::test]
async fn multi_audience_assertion_denies_in_strict_profile() {
    let jwt = external_user_jwt(
        json!([IMPORT_AUDIENCE, "https://praxis-api.example.com"]),
        None,
    );
    assert_import_denied_before_network(
        jwt.clone(),
        imported_user_extensions(&jwt, None),
        "exactly one audience",
    )
    .await;
}
```

Add one supported-mode and two unsupported-mode tests:

```rust
#[tokio::test]
async fn client_subject_import_is_eligible() {
    let jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::Client,
        RawInboundToken::new(
            jwt.clone(),
            Credential::Header { name: "Authorization".into() },
            TokenKind::Jwt,
        ),
    );
    let mut security = SecurityExtension::default();
    let mut client = ClientExtension::default();
    client.client_id = "external-client".into();
    security.client = Some(client);
    let mut extensions = Extensions::default();
    extensions.raw_credentials = Some(Arc::new(raw));
    extensions.security = Some(Arc::new(security));

    let http = idp(200, &json!({
        "access_token": "internal-token",
        "token_type": "Bearer"
    }).to_string());
    let mgr = build_import_manager(&http).await;
    let payload = build_payload_with_bearer(
        &jwt,
        "tool",
        "https://downstream.example.com",
        &["read"],
    )
    .with_subject(DelegationSubject::Client);

    let result = invoke_with_extensions(&mgr, payload, extensions).await;
    assert!(!result.continue_processing, "leg two is not implemented yet");
    let violation = result.violation.expect("the focused task ends at eligibility");
    assert_ne!(violation.code, "delegation.bad_request");
}

#[tokio::test]
async fn caller_workload_subject_import_is_rejected() {
    let jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let http = idp(200, "{}");
    let mgr = build_import_manager(&http).await;
    let payload = build_payload_with_bearer(
        &jwt,
        "tool",
        "https://downstream.example.com",
        &["read"],
    )
    .with_subject(DelegationSubject::CallerWorkload);

    let result = invoke_with_extensions(
        &mgr,
        payload,
        imported_user_extensions(&jwt, None),
    )
    .await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("unsupported mode must deny");
    assert_eq!(violation.code, "delegation.bad_request");
    assert!(violation.reason.contains("caller_workload"));
    assert_eq!(http.call_count_for(TOKEN_PATH), 0);
}

#[tokio::test]
async fn this_workload_subject_import_is_rejected() {
    let http = idp(200, "{}");
    let mgr = build_import_manager(&http).await;
    let payload = DelegationPayload::new("", "tool")
        .with_target_audience("https://downstream.example.com")
        .with_subject(DelegationSubject::ThisWorkload);

    let result = invoke_with_extensions(
        &mgr,
        payload,
        Extensions::default(),
    )
    .await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("unsupported mode must deny");
    assert!(violation.reason.contains("this_workload"));
    assert_eq!(http.call_count_for(TOKEN_PATH), 0);
}
```

- [ ] **Step 3: Run tests and verify they fail**

Run:

```bash
cargo test -p praxis-policy-builtins --test oauth subject_import
```

Expected: compilation succeeds after Task 1, but the handler still performs the old direct exchange. Tests fail because no eligibility denial exists.

- [ ] **Step 4: Implement eligibility validation**

In `delegator.rs`, import `TokenKind`, `TokenRole`, and `KeyBinding` through the existing extension import path. Add a private helper and method:

```rust
fn import_role(subject: &DelegationSubject) -> Option<TokenRole> {
    match subject {
        DelegationSubject::User => Some(TokenRole::User),
        DelegationSubject::Client => Some(TokenRole::Client),
        _ => None,
    }
}

fn audience_values(claims: &serde_json::Value) -> Vec<&str> {
    match claims.get("aud") {
        Some(serde_json::Value::String(aud)) => vec![aud.as_str()],
        Some(serde_json::Value::Array(auds)) => auds
            .iter()
            .filter_map(|aud| aud.as_str())
            .collect(),
        _ => Vec::new(),
    }
}
```

Inside `impl OAuthDelegator`, add:

```rust
fn validate_subject_import(
    &self,
    payload: &DelegationPayload,
    ext: &Extensions,
) -> Result<(), PluginViolation> {
    let Some(SubjectImportConfig::JwtBearer {
        authorization_server_audience,
    }) = self.typed.subject_import.as_ref()
    else {
        return Ok(());
    };

    let Some(role) = import_role(payload.subject()) else {
        return Err(PluginViolation::new(
            "delegation.bad_request",
            format!(
                "subject_import supports subject: user and subject: client, got {:?}",
                payload.subject()
            ),
        ));
    };

    let raw = ext
        .raw_credentials
        .as_ref()
        .and_then(|raw| raw.inbound_tokens.get(&role))
        .ok_or_else(|| PluginViolation::new(
            "delegation.bad_request",
            format!(
                "subject_import requires the selected inbound credential for {role:?}"
            ),
        ))?;

    if raw.kind != TokenKind::Jwt {
        return Err(PluginViolation::new(
            "delegation.bad_request",
            "subject_import requires the selected inbound credential to have TokenKind::Jwt",
        ));
    }

    let assertion = raw.token.as_str();
    if assertion != payload.bearer_token() {
        return Err(PluginViolation::new(
            "delegation.bad_request",
            "subject_import requires DelegationPayload.bearer_token to be the same credential selected by identity resolution",
        ));
    }

    let security_binding = match role {
        TokenRole::User => ext
            .security
            .as_ref()
            .and_then(|security| security.subject.as_ref())
            .map(|subject| subject.key_binding.as_ref()),
        TokenRole::Client => ext
            .security
            .as_ref()
            .and_then(|security| security.client.as_ref())
            .map(|client| client.key_binding.as_ref()),
        _ => None,
    };

    let binding = security_binding.ok_or_else(|| PluginViolation::new(
        "delegation.bad_request",
        format!("subject_import requires the resolved identity for {role:?}"),
    ))?;
    if binding.is_some() {
        return Err(PluginViolation::new(
            "delegation.bad_request",
            "subject_import cannot use a key-bound identity",
        ));
    }

    let Some(claims) = jwt_claims(assertion) else {
        return Err(PluginViolation::new(
            "delegation.bad_request",
            "subject_import could not decode the selected JWT claims",
        ));
    };

    let audiences = audience_values(&claims);
    if audiences.as_slice() != [authorization_server_audience.as_str()] {
        return Err(PluginViolation::new(
            "delegation.bad_request",
            format!(
                "subject_import requires exactly one audience value equal to the configured authorization_server_audience"
            ),
        ));
    }

    if claims.get("cnf").is_some_and(|value| !value.is_null()) {
        return Err(PluginViolation::new(
            "delegation.bad_request",
            "subject_import cannot use a JWT with a non-null cnf claim",
        ));
    }

    Ok(())
}
```

In `HookHandler<TokenDelegateHook>::handle`, after the target-audience check and before `cache_for`, add:

```rust
if let Err(violation) = self.validate_subject_import(payload, ext) {
    return PluginResult::deny(violation);
}
```

This placement is load-bearing: every cache hit also passes eligibility.

- [ ] **Step 5: Run focused tests and verify they pass**

Run:

```bash
cargo test -p praxis-policy-builtins --test oauth subject_import
```

Expected: all subject-import eligibility tests pass. The client test may fail at the next unimplemented network step, but it must not fail with `delegation.bad_request`.

- [ ] **Step 6: Commit**

```bash
git add crates/builtins/src/plugins/delegator_oauth/delegator.rs crates/builtins/tests/oauth/oauth_e2e.rs
git commit -m "feat: validate oauth jwt subject imports"
```

### Task 3: RFC 7523 Import Response and Request

**Files:**
- Modify: `crates/builtins/src/plugins/delegator_oauth/delegator.rs`
- Test: `crates/builtins/src/plugins/delegator_oauth/delegator.rs`

**Interfaces:**
- Consumes: existing `token_request`, `basic_auth_header`, `with_idempotency_key`, `audit_mint`, and `idp_rejection`.
- Produces: private `struct JwtBearerGrantResponse`, private `fn validate_jwt_bearer_response(&JwtBearerGrantResponse) -> Result<(), PluginViolation>`, and private `async fn import_subject_token(&self, assertion: &str, ext: &Extensions) -> Result<String, PluginViolation>`.

- [ ] **Step 1: Write failing response tests**

Add a test module near `response_validation_tests`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod jwt_bearer_response_tests {
    use super::*;

    fn response(access_token: &str, token_type: &str) -> JwtBearerGrantResponse {
        JwtBearerGrantResponse {
            access_token: access_token.to_owned(),
            token_type: token_type.to_owned(),
            expires_in: Some(300),
        }
    }

    #[test]
    fn accepts_non_empty_bearer_token_type_case_insensitively() {
        validate_jwt_bearer_response(&response("token", "Bearer")).unwrap();
        validate_jwt_bearer_response(&response("token", "bearer")).unwrap();
    }

    #[test]
    fn rejects_empty_access_token() {
        let error = validate_jwt_bearer_response(&response("", "Bearer")).unwrap_err();
        assert_eq!(error.code, "delegation.bad_response");
    }

    #[test]
    fn rejects_missing_or_empty_token_type_semantics() {
        for token_type in ["", "   "] {
            let error =
                validate_jwt_bearer_response(&response("token", token_type)).unwrap_err();
            assert_eq!(error.code, "delegation.bad_response");
        }
    }

    #[test]
    fn rejects_non_bearer_token_type() {
        let error = validate_jwt_bearer_response(&response("token", "DPoP")).unwrap_err();
        assert_eq!(error.code, "delegation.bad_response");
        assert!(error.reason.contains("Bearer"));
    }
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p praxis-policy-builtins jwt_bearer_response_tests
```

Expected: compilation fails because the response type and validator do not exist.

- [ ] **Step 3: Implement the response model and validator**

Near `TokenExchangeResponse`, add:

```rust
const GRANT_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Successful RFC 7523 JWT Authorization Grant response subset.
///
/// This is deliberately separate from `TokenExchangeResponse`: RFC 6749
/// requires `token_type`, while RFC 8693 has its own `issued_token_type`
/// semantics.
#[derive(Debug, Deserialize)]
struct JwtBearerGrantResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<i64>,
}

fn validate_jwt_bearer_response(
    response: &JwtBearerGrantResponse,
) -> Result<(), PluginViolation> {
    if response.access_token.is_empty() {
        return Err(PluginViolation::new(
            "delegation.bad_response",
            "authorization server omitted access_token from the JWT bearer grant response",
        ));
    }
    if response.token_type.trim().is_empty() {
        return Err(PluginViolation::new(
            "delegation.bad_response",
            "authorization server omitted token_type from the JWT bearer grant response",
        ));
    }
    if !response.token_type.trim().eq_ignore_ascii_case("Bearer") {
        return Err(PluginViolation::new(
            "delegation.bad_response",
            "JWT bearer grant returned a token_type other than Bearer",
        ));
    }
    Ok(())
}
```

Keep `expires_in` modeled but unused in version one; the internal token's lifetime is owned by the internal authorization server and is not cached separately.

- [ ] **Step 4: Implement the import request**

Inside `impl OAuthDelegator`, add:

```rust
async fn import_subject_token(
    &self,
    assertion: &str,
    ext: &Extensions,
) -> Result<String, PluginViolation> {
    let form = [
        ("grant_type", GRANT_TYPE_JWT_BEARER),
        ("assertion", assertion),
    ];
    let key = new_effect_key();
    let request = self
        .token_request(&form)
        .and_then(|request| request.header("authorization", self.basic_auth_header()))
        .and_then(|request| self.with_idempotency_key(request, &key))
        .map_err(|violation| *violation)?;

    self.audit_mint(
        ext,
        &key,
        "JWT bearer subject import",
        &[("leg", "jwt_bearer_import")],
        || async {
            let response = ext
                .http_request(request, RetryPolicy::undelivered_only())
                .await
                .map_err(|error| {
                    self.violation_for("JWT bearer import POST", &error)
                })?;

            if !response.is_success() {
                return Err(idp_rejection("JWT bearer import", &response));
            }

            let parsed = serde_json::from_slice::<JwtBearerGrantResponse>(&response.body)
                .map_err(|error| PluginViolation::new(
                    "delegation.bad_response",
                    format!("JWT bearer import response wasn't valid token JSON: {error}"),
                ))?;
            validate_jwt_bearer_response(&parsed)?;
            Ok(parsed.access_token)
        },
    )
    .await
}
```

Do not add `scope`, subject, actor, or client-assertion fields to `form`.

- [ ] **Step 5: Run focused tests and verify they pass**

Run:

```bash
cargo test -p praxis-policy-builtins jwt_bearer_response_tests
```

Expected: all response validation tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/builtins/src/plugins/delegator_oauth/delegator.rs
git commit -m "feat: add oauth jwt bearer import grant"
```

### Task 4: RFC 8693 Integration and Subject Continuity

**Files:**
- Modify: `crates/builtins/src/plugins/delegator_oauth/delegator.rs`
- Test: `crates/builtins/tests/oauth/oauth_e2e.rs`

**Interfaces:**
- Consumes: `import_subject_token`, existing `exchange`, `validate_exchange_response`.
- Produces: imported-path behavior where leg two uses the internal access token and the access-token type URN, actor parameters remain on leg two, and external identity is never used as the subject fallback.

- [ ] **Step 1: Write failing two-leg protocol test**

Add JWT and response helpers:

```rust
fn internal_base_jwt() -> String {
    jwt_with_claims(json!({
        "iss": "https://internal-idp.example.com/realms/internal",
        "sub": "internal-alice",
        "aud": IMPORT_AUDIENCE,
        "exp": 4102444800
    }))
}

fn final_downstream_jwt() -> String {
    jwt_with_claims(json!({
        "iss": "https://internal-idp.example.com/realms/internal",
        "sub": "internal-alice",
        "aud": "https://downstream.example.com",
        "scope": "read audit",
        "exp": 4102444800
    }))
}

fn import_response() -> String {
    json!({
        "access_token": internal_base_jwt(),
        "token_type": "Bearer",
        "expires_in": 300
    })
    .to_string()
}

fn exchange_response() -> String {
    json!({
        "access_token": final_downstream_jwt(),
        "issued_token_type":
            "urn:ietf:params:oauth:token-type:access_token",
        "expires_in": 300,
        "scope": "read audit"
    })
    .to_string()
}
```

Add the test:

```rust
#[tokio::test]
async fn jwt_import_uses_two_protocol_legs() {
    let http = Arc::new(
        FakeTransport::new()
            .json(TOKEN_PATH, 200, &import_response())
            .json(TOKEN_PATH, 200, &exchange_response()),
    );
    let mgr = build_import_manager(&http).await;
    let external_jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let payload = build_payload_with_bearer(
        &external_jwt,
        "tool",
        "https://downstream.example.com",
        &["read"],
    )
    .with_actor_role(TokenRole::CallerWorkload)
    .with_actor(TokenRole::CallerWorkload, "actor-token");

    let result = invoke_with_extensions(
        &mgr,
        payload,
        imported_user_extensions(&external_jwt, None),
    )
    .await;
    assert!(
        result.continue_processing,
        "two-leg exchange should succeed: {:?}",
        result.violation
    );

    let requests = http.requests();
    assert_eq!(requests.len(), 2);
    let import_body = String::from_utf8_lossy(&requests[0].body).into_owned();
    let exchange_body = String::from_utf8_lossy(&requests[1].body).into_owned();

    assert!(import_body.contains(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
    ));
    assert!(import_body.contains("assertion="));
    for forbidden in [
        "subject_token=",
        "subject_token_type=",
        "actor_token=",
        "actor_token_type=",
        "client_assertion=",
        "client_assertion_type=",
        "scope=",
    ] {
        assert!(!import_body.contains(forbidden), "{forbidden} on leg one");
    }

    assert!(exchange_body.contains(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
    ));
    assert!(exchange_body.contains("subject_token="));
    assert!(exchange_body.contains(
        "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
    ));
    assert!(exchange_body.contains("audience=https%3A%2F%2Fdownstream.example.com"));
    assert!(exchange_body.contains("scope=read"));
    assert!(exchange_body.contains("actor_token=actor-token"));

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    assert_eq!(
        final_payload.delegated_token.as_ref().map(|token| token.token.as_str()),
        Some(final_downstream_jwt().as_str())
    );
}
```

Add a subject-federation test:

```rust
#[tokio::test]
async fn imported_subject_may_differ_from_external_subject() {
    let http = Arc::new(
        FakeTransport::new()
            .json(TOKEN_PATH, 200, &import_response())
            .json(TOKEN_PATH, 200, &exchange_response()),
    );
    let mgr = build_import_manager(&http).await;
    let external_jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let payload = build_payload_with_bearer(
        &external_jwt,
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

    let result = invoke_with_extensions(
        &mgr,
        payload,
        imported_user_extensions(&external_jwt, None),
    )
    .await;
    assert!(
        result.continue_processing,
        "internal sub internal-alice must not be compared with external sub external-alice: {:?}",
        result.violation
    );
}
```

Add an opaque-internal-token strict-validation test:

```rust
#[tokio::test]
async fn opaque_internal_token_with_readable_final_jwt_is_subject_unverifiable() {
    let opaque_import = json!({
        "access_token": "opaque-internal-token",
        "token_type": "Bearer"
    })
    .to_string();
    let http = Arc::new(
        FakeTransport::new()
            .json(TOKEN_PATH, 200, &opaque_import)
            .json(TOKEN_PATH, 200, &exchange_response()),
    );
    let mgr = build_import_manager(&http).await;
    let external_jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let payload = build_payload_with_bearer(
        &external_jwt,
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

    let result = invoke_with_extensions(
        &mgr,
        payload,
        imported_user_extensions(&external_jwt, None),
    )
    .await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("strict validation must deny");
    assert_eq!(violation.code, "delegation.subject_unverifiable");
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p praxis-policy-builtins --test oauth jwt_import_uses_two_protocol_legs
cargo test -p praxis-policy-builtins --test oauth imported_subject_may_differ
cargo test -p praxis-policy-builtins --test oauth opaque_internal_token
```

Expected: the first two fail because leg two still uses the external bearer and configured inbound subject token type. The third may already fail for the same reason.

- [ ] **Step 3: Integrate the import leg into `exchange`**

At the start of `exchange`, calculate:

```rust
let imported = self.typed.subject_import.is_some()
    && matches!(
        payload.subject(),
        DelegationSubject::User | DelegationSubject::Client
    );
```

Change subject-token selection to:

```rust
let subject_token: Cow<str> = if is_workload {
    match self.mint_base_token(bearer, ext).await {
        Ok(token) => Cow::Owned(token),
        Err(violation) => return Err(violation),
    }
} else if imported {
    match self.import_subject_token(bearer, ext).await {
        Ok(token) => Cow::Owned(token),
        Err(violation) => return Err(violation),
    }
} else {
    Cow::Borrowed(bearer)
};
```

Immediately before building the form, add:

```rust
let subject_token_type = if imported {
    "urn:ietf:params:oauth:token-type:access_token"
} else {
    self.typed.subject_token_type.as_str()
};
```

Replace the configured type in the RFC 8693 form with:

```rust
("subject_token_type", subject_token_type),
```

Keep all actor logic exactly where it is; it already belongs only to leg two.

- [ ] **Step 4: Suppress the external fallback**

In the strict-response-validation block, compute `caller_identity` as:

```rust
let caller_identity = if imported {
    None
} else {
    match payload.subject() {
        DelegationSubject::User => ext
            .security
            .as_ref()
            .and_then(|security| security.subject.as_ref())
            .and_then(|subject| subject.id.as_deref()),
        DelegationSubject::Client => ext
            .security
            .as_ref()
            .and_then(|security| security.client.as_ref())
            .map(|client| client.client_id.as_str()),
        DelegationSubject::CallerWorkload => ext
            .security
            .as_ref()
            .and_then(|security| security.caller_workload.as_ref())
            .and_then(|workload| workload.spiffe_id.as_deref()),
        DelegationSubject::ThisWorkload => None,
        _ => None,
    }
};
```

Do not change `validate_exchange_response` itself. Its existing subject-token-first behavior is correct once the internal token is passed as `subject_token`.

- [ ] **Step 5: Add leg labels to the second mint effect**

In the second `audit_mint` details array, add the leg label:

```rust
&[
    ("leg", "token_exchange"),
    ("audience", audience),
    ("scope", scope.as_str()),
]
```

- [ ] **Step 6: Run focused tests and verify they pass**

Run:

```bash
cargo test -p praxis-policy-builtins --test oauth jwt_import_uses_two_protocol_legs
cargo test -p praxis-policy-builtins --test oauth imported_subject_may_differ
cargo test -p praxis-policy-builtins --test oauth opaque_internal_token
```

Expected: all three pass.

- [ ] **Step 7: Commit**

```bash
git add crates/builtins/src/plugins/delegator_oauth/delegator.rs crates/builtins/tests/oauth/oauth_e2e.rs
git commit -m "feat: import jwt subjects before token exchange"
```

### Task 5: Cache-Key Import Isolation

**Files:**
- Modify: `crates/builtins/src/plugins/delegator_oauth/cache/key.rs`
- Modify: `crates/builtins/src/plugins/delegator_oauth/delegator.rs`
- Test: `crates/builtins/src/plugins/delegator_oauth/cache/key.rs`

**Interfaces:**
- Consumes: existing `derive`, `DelegatorIdentity`, and `DelegationPayload`.
- Produces: `pub(in crate::plugins::delegator_oauth) enum SubjectImportMode<'a>` with `Direct` and `JwtBearer { audience: &'a str }`, and `derive(..., subject_import: SubjectImportMode<'_>)`.

- [ ] **Step 1: Write failing cache-key test**

In the existing `key.rs` test module, add:

```rust
#[test]
fn direct_and_imported_subjects_use_distinct_cache_domains() {
    let secret = secret();
    let delegator = delegator();
    let payload = base();

    let direct = derive(
        &secret,
        delegator,
        &payload,
        SubjectImportMode::Direct,
    )
    .unwrap();
    let imported = derive(
        &secret,
        delegator,
        &payload,
        SubjectImportMode::JwtBearer {
            audience: "https://internal-idp.example.com/realms/internal",
        },
    )
    .unwrap();
    let other_audience = derive(
        &secret,
        delegator,
        &payload,
        SubjectImportMode::JwtBearer {
            audience: "https://other-idp.example.com",
        },
    )
    .unwrap();

    assert_ne!(direct, imported);
    assert_ne!(imported, other_audience);
}
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
cargo test -p praxis-policy-builtins direct_and_imported_subjects_use_distinct_cache_domains
```

Expected: compilation fails because `SubjectImportMode` and the new `derive` parameter do not exist.

- [ ] **Step 3: Encode import mode in the key**

Add:

```rust
#[derive(Debug, Clone, Copy)]
pub(in crate::plugins::delegator_oauth) enum SubjectImportMode<'a> {
    Direct,
    JwtBearer { audience: &'a str },
}
```

Change the domain constant to:

```rust
const DOMAIN: &[u8] = b"ppe.delegation.cache.v2";
```

Add the `subject_import: SubjectImportMode<'_>` parameter to the existing `derive` signature. Keep every existing validation branch and encoded component in its current order. Immediately after this existing line:

```rust
enc.tag(subject_tag);
```

insert this block:

```rust
    match subject_import {
        SubjectImportMode::Direct => enc.tag(0x00),
        SubjectImportMode::JwtBearer { audience } => {
            enc.tag(0x01).str(audience);
        },
    }
}
```

Update every existing `derive(...)` call in the `key.rs` test module to pass
`SubjectImportMode::Direct` as the final argument, including `key_of`:

```rust
fn key_of(payload: &DelegationPayload, secret: &KeySecret) -> CacheKey {
    derive(secret, delegator(), payload, SubjectImportMode::Direct)
        .expect("base payload is cacheable")
}
```

- [ ] **Step 4: Pass the mode from the delegator**

Extend the existing cache-key import in `delegator.rs` with `SubjectImportMode`.
In `cache_for`, before calling `derive_cache_key`, build:

```rust
let subject_import = match self.typed.subject_import.as_ref() {
    None => SubjectImportMode::Direct,
    Some(SubjectImportConfig::JwtBearer {
        authorization_server_audience,
    }) => SubjectImportMode::JwtBearer {
        audience: authorization_server_audience,
    },
};
```

Pass it as the final argument to `derive_cache_key`.

- [ ] **Step 5: Run focused tests and verify they pass**

Run:

```bash
cargo test -p praxis-policy-builtins direct_and_imported_subjects_use_distinct_cache_domains
```

Expected: the new cache-domain test passes.

- [ ] **Step 6: Commit**

```bash
git add crates/builtins/src/plugins/delegator_oauth/cache/key.rs crates/builtins/src/plugins/delegator_oauth/delegator.rs
git commit -m "feat: isolate imported oauth cache entries"
```

### Task 6: Failure, Cache, and Backward-Compatibility Coverage

**Files:**
- Modify: `crates/builtins/tests/oauth/oauth_e2e.rs`
- Modify: `crates/builtins/tests/oauth/cache_e2e.rs`

**Interfaces:**
- Consumes: the helpers and imported path from Tasks 2-5.
- Produces: regression coverage for malformed import responses, leg-two failure, retry semantics, cache behavior, and unchanged direct exchange.

- [ ] **Step 1: Add import failure tests**

```rust
#[tokio::test]
async fn malformed_jwt_bearer_response_denies_delegation() {
    let http = idp(200, "{not-json}");
    let mgr = build_import_manager(&http).await;
    let jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let payload = build_payload_with_bearer(
        &jwt,
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

    let result = invoke_with_extensions(
        &mgr,
        payload,
        imported_user_extensions(&jwt, None),
    )
    .await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("malformed import response");
    assert_eq!(violation.code, "delegation.bad_response");
    assert!(!violation.reason.contains(&jwt));
}

#[tokio::test]
async fn jwt_bearer_rejection_does_not_echo_assertion_or_body() {
    let body = json!({
        "error": "invalid_grant",
        "error_description": "assertion 'secret-value' is not active"
    })
    .to_string();
    let http = idp(400, &body);
    let mgr = build_import_manager(&http).await;
    let jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let payload = build_payload_with_bearer(
        &jwt,
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

    let result = invoke_with_extensions(
        &mgr,
        payload,
        imported_user_extensions(&jwt, None),
    )
    .await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("IdP rejection must deny");
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(violation.reason.contains("invalid_grant"));
    assert!(!violation.reason.contains("secret-value"));
    assert!(!violation.reason.contains(&jwt));
}
```

Add a table-driven response validator test if it is not already covered:

```rust
#[tokio::test]
async fn invalid_jwt_bearer_response_metadata_denies() {
    for body in [
        json!({ "access_token": "token" }).to_string(),
        json!({ "token_type": "Bearer" }).to_string(),
        json!({ "access_token": "", "token_type": "Bearer" }).to_string(),
        json!({ "access_token": "token", "token_type": "" }).to_string(),
        json!({ "access_token": "token", "token_type": "DPoP" }).to_string(),
    ] {
        let http = idp(200, &body);
        let mgr = build_import_manager(&http).await;
        let jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
        let payload = build_payload_with_bearer(
            &jwt,
            "tool",
            "https://downstream.example.com",
            &["read"],
        );
        let result = invoke_with_extensions(
            &mgr,
            payload,
            imported_user_extensions(&jwt, None),
        )
        .await;
        assert!(!result.continue_processing, "body must be rejected: {body}");
        assert_eq!(
            result.violation.expect("response must deny").code,
            "delegation.bad_response"
        );
    }
}
```

- [ ] **Step 2: Add cache-hit and leg-failure tests**

In `cache_e2e.rs`, add an imported cache fixture using the same response helpers and assert:

```rust
#[tokio::test]
async fn imported_cache_hit_skips_both_network_legs() {
    let http = Arc::new(
        FakeTransport::new()
            .json(TOKEN_PATH, 200, &import_response())
            .json(TOKEN_PATH, 200, &exchange_response()),
    );
    // Build the delegator with cache enabled, subject_import enabled,
    // and the capabilities used by build_import_manager.
    let mgr = build_import_cache_manager(&http).await;
    let jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let extensions = imported_user_extensions(&jwt, None);
    let payload = imported_payload(&jwt);

    let first = invoke_with_extensions(&mgr, payload.clone(), extensions.clone()).await;
    let second = invoke_with_extensions(&mgr, payload, extensions).await;

    assert!(first.continue_processing);
    assert!(second.continue_processing);
    assert_eq!(http.call_count_for(TOKEN_PATH), 2);

    let final_payload = DelegationPayload::from_pipeline_result(&second).unwrap();
    assert_eq!(
        final_payload.metadata.get("delegated_token_source"),
        Some(&serde_json::json!("cache"))
    );
}
```

Implement `build_import_cache_manager` by extending the existing cache test builder with:

```rust
config["cache"] = json!({
    "enabled": true,
    "ttl_ceiling_seconds": 60
});
config["subject_import"] = json!({
    "kind": "jwt_bearer",
    "authorization_server_audience": IMPORT_AUDIENCE
});
```

Use the exact cache field names from the existing `cache_e2e.rs`; preserve its current cache TTL and serve-window settings where they differ.

Add:

```rust
#[tokio::test]
async fn exchange_failure_after_successful_import_denies_whole_delegation() {
    let http = Arc::new(
        FakeTransport::new()
            .json(TOKEN_PATH, 200, &import_response())
            .json(TOKEN_PATH, 400, &json!({
                "error": "invalid_scope"
            }).to_string()),
    );
    let mgr = build_import_manager(&http).await;
    let jwt = external_user_jwt(json!(IMPORT_AUDIENCE), None);
    let payload = build_payload_with_bearer(
        &jwt,
        "tool",
        "https://downstream.example.com",
        &["read"],
    );

    let result = invoke_with_extensions(
        &mgr,
        payload,
        imported_user_extensions(&jwt, None),
    )
    .await;
    assert!(!result.continue_processing);
    assert_eq!(
        result.violation.expect("leg-two failure must deny").code,
        "delegation.idp_rejected"
    );
}
```

- [ ] **Step 3: Add backward-compatibility assertions**

Run the complete existing OAuth suite before adding any compatibility-only code:

```bash
cargo test -p praxis-policy-builtins --test oauth
```

Expected: all existing direct-exchange, workload, actor, error, and cache tests pass. If an existing helper signature changes because of the cache-key parameter, update only its call sites; do not change request semantics.

- [ ] **Step 4: Run the focused new tests**

```bash
cargo test -p praxis-policy-builtins --test oauth jwt_bearer
cargo test -p praxis-policy-builtins --test oauth imported_cache_hit
cargo test -p praxis-policy-builtins --test oauth exchange_failure_after_successful_import
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/builtins/tests/oauth/oauth_e2e.rs crates/builtins/tests/oauth/cache_e2e.rs
git commit -m "test: cover oauth jwt subject import"
```

### Task 7: Documentation

**Files:**
- Modify: `docs/content/apl/delegation.md`
- Modify: `docs/content/guides/identity-delegation.md`

**Interfaces:**
- Consumes: final behavior from Tasks 1-6.
- Produces: operator-facing configuration, prerequisites, trust boundaries, limitations, and Keycloak compatibility guidance.

- [ ] **Step 1: Document the plugin configuration**

In `docs/content/apl/delegation.md`, extend the `delegator/oauth` section with:

```yaml
plugins:
  - name: workday-oauth
    kind: delegator/oauth
    hooks: [token.delegate]
    capabilities:
      - perform_http
      - read_inbound_credentials
      - read_subject
      - read_client
    config:
      token_endpoint: "https://internal-idp.example.com/realms/internal/protocol/openid-connect/token"
      client_id: "ppe-gateway"
      client_secret_source:
        kind: file
        path: /etc/ppe-secrets/client-secret
      subject_import:
        kind: jwt_bearer
        authorization_server_audience: "https://internal-idp.example.com/realms/internal"
      default_outbound_header: "Authorization"
```

State that `subject_import` is optional, supports only `subject: user` and `subject: client`, and leaves all existing behavior unchanged when omitted.

- [ ] **Step 2: Document the protocol and prerequisites**

In `identity-delegation.md`, add a section titled `Importing an external JWT before exchange` containing:

```text
PPE first presents the verified external JWT to the internal authorization
server as an RFC 7523 JWT Authorization Grant:

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
assertion=<external JWT>

The returned internal access token is then used as the RFC 8693 subject_token
for the existing downstream token exchange. PPE does not send actor, audience,
scope, or client-assertion parameters on the import leg.
```

Document these prerequisites:

```markdown
- The external issuer must issue a short-lived JWT whose single audience is the configured internal authorization-server audience.
- The JWT must include a unique `jti` for providers that reject assertion replay.
- The inbound identity resolver must still validate the JWT normally.
- The selected credential must be a bearer JWT: it must not be key-bound and must not contain a non-null `cnf` claim.
- The internal authorization server owns assertion validation, federated subject mapping, scopes, and internal-token lifetime.
- Keycloak requires a JWT Authorization Grant identity provider, an allowed confidential client, explicit allowed audience, a pre-linked federated identity, and a short assertion lifetime.
- Keycloak client-subject interoperability is not yet runtime-verified.
```

- [ ] **Step 3: Document trust boundaries and limitations**

Add this exact set of limitations:

```markdown
- Version one does not acquire assertions from an upstream authorization mechanism.
- Version one does not request import-leg scopes.
- Version one does not cache internal base tokens.
- A cache hit skips both the import and exchange legs.
- Direct and imported delegated-token cache entries are separated by import mode and audience.
- Import and exchange failures each deny the whole delegation.
- Retries remain undelivered-only because an assertion or token exchange may have succeeded before the response was lost.
```

Explain that external and internal `sub` values may differ and that PPE compares the final delegated JWT subject with the internal base-token subject, not with the external caller identity.

- [ ] **Step 4: Run docs validation**

Run the repository's existing docs validation command. If `docs/INDEX.md` or the repository root does not define one, run:

```bash
cargo test -p praxis-policy-builtins --test oauth
```

and report that no separate docs validator is configured.

- [ ] **Step 5: Commit**

```bash
git add docs/content/apl/delegation.md docs/content/guides/identity-delegation.md
git commit -m "docs: describe oauth jwt subject import"
```

### Task 8: Optional Live Keycloak Interoperability Test

**Files:**
- Create: `crates/ppe/tests/oauth_import_live.rs`

**Interfaces:**
- Consumes: final imported delegation path.
- Produces: an ignored-by-default live test that can exercise a preconfigured two-domain Keycloak environment.

- [ ] **Step 1: Add an ignored live test**

Create `oauth_import_live.rs`:

```rust
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "live integration test"
)]

use std::sync::Arc;

use praxis_policy::http_hyper::HyperTransport;
use praxis_policy::{OAuthDelegatorFactory, OAUTH_KIND};
use praxis_policy_core::config::PolicyConfig;
use praxis_policy_core::delegation::{
    DelegationPayload, HOOK_TOKEN_DELEGATE, TokenDelegateHook,
};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::factory::PluginFactoryRegistry;
use praxis_policy_core::extensions::raw_credentials::{
    Credential, RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
};
use praxis_policy_core::extensions::security::{SecurityExtension, SubjectExtension};
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
    let downstream_audience =
        std::env::var("PPE_IMPORT_LIVE_DOWNSTREAM_AUDIENCE").unwrap();

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

    let payload = DelegationPayload::new(
        external_jwt.clone(),
        "live-downstream",
    )
    .with_target_audience(downstream_audience)
    .with_required_permissions(vec!["read".to_owned()]);

    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new(
            external_jwt,
            Credential::Header { name: "Authorization".into() },
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
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            extensions,
            None,
        )
        .await;
    assert!(
        result.continue_processing,
        "live Keycloak import failed: {:?}",
        result.violation
    );
}
```

This test intentionally does not create or configure realms. Its environment contract makes the external setup explicit and prevents CI from claiming compatibility without a live provider.

- [ ] **Step 2: Verify the ignored test compiles**

Run:

```bash
cargo test -p praxis-policy --features oauth,http-hyper \
  --test oauth_import_live --no-run
```

Expected: compilation succeeds.

- [ ] **Step 3: Commit**

```bash
git add crates/ppe/tests/oauth_import_live.rs
git commit -m "test: add live keycloak jwt import scenario"
```

## Final Verification

Run once after all tasks are complete:

```bash
cargo fmt --all
cargo test -p praxis-policy-builtins --test oauth
cargo test -p praxis-policy-builtins delegator_oauth
cargo test -p praxis-policy --features oauth,http-hyper \
  --test oauth_import_live --no-run
```

If repository policy requires workspace-wide validation, also run the existing workspace test command from the repository root. Do not invent a new comprehensive command.

Expected results:

- All direct OAuth delegator tests pass unchanged in behavior.
- All subject-import eligibility, protocol, response, subject-continuity, failure, and cache tests pass.
- No Praxis Core files are modified.
- No Helm chart or Praxis Core change appears in the final diff.
