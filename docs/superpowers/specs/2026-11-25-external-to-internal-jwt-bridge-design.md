# External-to-Internal JWT Authorization Grant Design

Status: revised design for review; no production implementation has been made.

## Executive Summary

Praxis has the right architectural boundary already. An inbound external JWT
is authenticated by `identity/jwt`, PPE authorization policy runs, and
`delegator/oauth` obtains the downstream credential. What is missing is a
credential-domain bridge for `subject: user` and `subject: client`: the OAuth
delegator currently presents those inbound bearers directly as RFC 8693
`subject_token` values. That is correct when the internal authorization server
issued or already trusts the credential, but it cannot convert an external
credential into an internal one.

The recommended design is a two-leg, standards-based bridge:

```text
External JWT
    |
    v
PPE identity resolution and authorization policy
    |
    v
RFC 7523 JWT Authorization Grant
    |
    v
Internal access token
    |
    v
Existing RFC 8693 token exchange
    |
    v
Downstream access token
```

The existing `subject: caller_workload` path already uses two token-endpoint
legs, so this is an extension of an established execution shape rather than a
new delegation architecture. The protocol semantics remain distinct:

- The new first leg uses the external JWT as an RFC 7523 authorization grant:
  `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and
  `assertion=<external JWT>`.
- The existing workload first leg uses a JWT-SVID for RFC 7523 client
  authentication: `client_assertion_type` and `client_assertion`.
- The second leg uses the internal access token as the RFC 8693
  `subject_token` and continues to apply target audience, scopes, and actor
  semantics.

The proposed optional configuration remains:

```yaml
subject_import:
  kind: jwt_bearer
  authorization_server_audience: https://internal-idp.example.com/realms/internal
```

Version one should support only `subject: user` and `subject: client`, omit
import-leg `scope`, and avoid an intermediate-token cache. It should require an
explicit import audience, reject confirmation-bearing JWTs, model and validate
the RFC 7523 response, run eligibility before cache lookup, and suppress only
the external-identity fallback in final subject validation.

## Source Baselines

This revision used only the locally available repositories. No remote was
accessed during this revision.

| Repository | Local path | Branch | Commit |
| --- | --- | --- | --- |
| Praxis Policy Engine | `/home/vbelouso/repo/projects/praxis/praxis-ppe` | `main` | `b8383d5a56664fb38db4ed0eebacd9529122b5bb` |
| Praxis Core | `/home/vbelouso/repo/projects/praxis/praxis-core` | local checkout | `ee2844f745623b0b2c84a0413b536c21256371ac` |
| Praxis AI | `/home/vbelouso/repo/projects/praxis/praxis-ai` | local checkout | `bcdcfdbcf9635ea1192b62088355fc98090da15e` |
| Keycloak | `/home/vbelouso/repo/projects/keycloak/keycloak` | `main` | `c99eacd33bc0b52ab47beac7bc5e97f4bfdb3a36` |

Previously observed local upstream refs were:

- PPE upstream `main`: `842f8250b4266e74f8970537ac884beaf4261778`
- Praxis Core upstream: `fd88bf41a612c91109e4a65219019fc7907ab645`
- Praxis AI upstream: `f7715c6e1fddff5c5dbb75163c5ccb12d7268309`
- Keycloak upstream: `b58f23e8d3510a792ef653d8a766bc2cd642be52`

The PPE checkout is three commits behind the observed upstream ref, but the
files relevant to this design are unchanged by that delta. No branch, merge,
rebase, or repository-history operation was performed.

## Current PPE Execution Path

The current path is:

1. The HTTP filter extracts the inbound credential and makes it available to
   identity resolution.
2. `identity/jwt` verifies the credential and records it in
   `RawCredentialsExtension.inbound_tokens`. The resolver's documented contract
   is in
   `crates/builtins/src/plugins/identity_jwt/resolver.rs:26`, and the raw token
   is inserted at `crates/builtins/src/plugins/identity_jwt/resolver.rs:1156`.
3. The resolver writes the selected identity to `SecurityExtension`. The
   extension is defined in
   `crates/ppe-core/src/extensions/security.rs:357`.
4. PPE policy decides whether delegation is permitted. This occurs before the
   OAuth delegator obtains a new credential.
5. APL delegation constructs a `DelegationPayload`. The payload contains the
   selected bearer bytes, subject mode, target audience, permissions, actor
   credential, and delegation metadata. The type is defined in
   `crates/ppe-core/src/delegation/payload.rs:229`.
6. `OAuthDelegator::handle` validates the bearer and audience and invokes
   `exchange` through the optional delegated-token cache. See
   `crates/builtins/src/plugins/delegator_oauth/delegator.rs:941`.
7. For ordinary user and client subjects, `exchange` uses the inbound bearer
   directly as RFC 8693 `subject_token` and sends the configured
   `subject_token_type`. See
   `crates/builtins/src/plugins/delegator_oauth/delegator.rs:619` and
   `:648`.
8. For `subject: caller_workload`, `exchange` first calls `mint_base_token`.
   That function sends `client_assertion_type` and `client_assertion` using
   `client_credentials`, then uses the returned base token as the RFC 8693
   subject token. See
   `crates/builtins/src/plugins/delegator_oauth/delegator.rs:231` and `:351`.
9. The RFC 8693 response is parsed as `TokenExchangeResponse` at
   `crates/builtins/src/plugins/delegator_oauth/delegator.rs:752`.
10. `validate_exchange_response` checks issued token type, granted scopes, JWT
    audience, and subject continuity at
    `crates/builtins/src/plugins/delegator_oauth/delegator.rs:1263`.
11. The final token is placed in `delegated_token`, and downstream forwarding
    injects it in the configured outbound header.

The existing cache key already includes the delegator instance, token endpoint,
client identity, subject mode, credential bytes, actor role and token, target
name, type, audience, permissions, trust domain, enforcement mode, and route
attenuation. See
`crates/builtins/src/plugins/delegator_oauth/cache/key.rs:181` and `:377`.

### Reusable Mechanisms

The feature can reuse, without redesign:

- Inbound JWT verification and raw credential storage.
- PPE authorization and APL delegation policy.
- `DelegationPayload` construction.
- The OAuth client's existing client authentication.
- Token-endpoint form encoding, HTTPS enforcement, response-size limit, timeout,
  and transport error classification.
- Effect recording and `undelivered_only` retry semantics.
- Final RFC 8693 audience, scope, actor, and issued-token-type handling.
- Delegated-token caching and downstream injection.

No Praxis Core change is required. In particular, `RawInboundToken.kind` and the
selected `SecurityExtension` identity are already available through
`Extensions` to the delegator. Extending `DelegationPayload` with token-kind
metadata is unnecessary.

## Standards Assessment

Normative citations used by this design are:

- RFC 7523 §2.1 defines the JWT bearer authorization grant parameters
  `grant_type` and `assertion`.
- RFC 7523 §3 requires the authorization server to validate assertion
  signature or MAC, issuer, subject, audience, expiration, and optional
  not-before.
- RFC 7521 §4.1 defines the assertion grant request and permits optional
  `scope`.
- RFC 7521 §3 describes the assertion framework as intended for bearer
  assertions and not directly suitable for holder-of-key assertions.
- RFC 7521 §4.1 recommends that authorization servers not issue access tokens
  with lifetimes significantly exceeding assertion validity.
- RFC 6749 §5.1 requires successful token responses to include `access_token`
  and `token_type`.
- RFC 8693 §2.1 defines token exchange request parameters, including
  `subject_token`, `subject_token_type`, `audience`, `scope`, `actor_token`,
  and `actor_token_type`.
- RFC 8693 §3 distinguishes access-token and JWT token types.
- RFC 7519 §4.1.4 defines the JWT `aud` claim.
- RFC 8725 §3 and §4 require explicit algorithm selection, audience validation,
  and validation rules that cannot be combined in contradictory ways.
- RFC 9700 §2.2.1 recommends sender-constrained access tokens where feasible.
- RFC 9700 §2.5 recommends asymmetric client authentication where feasible.
- RFC 10070 §4 updates RFC 7523 audience handling for authorization grants: the
  client is responsible for presenting an assertion to an appropriate
  authorization server, and the authorization server may be identified by an
  issuer identifier or token endpoint URL.

These are protocol requirements and recommendations, not Keycloak-specific
behavior. Provider restrictions are recorded separately below.

## Keycloak Compatibility Assessment

The local Keycloak implementation has a dedicated JWT Authorization Grant
path:

- `services/src/main/java/org/keycloak/protocol/oidc/grants/JWTAuthorizationGrantType.java`
  validates the assertion, resolves the identity provider, checks audience and
  activity, and creates the user session.
- `services/src/main/java/org/keycloak/protocol/oidc/grants/DefaultJWTAuthorizationGrantValidator.java`
  rejects clients for which JWT Authorization Grant is not enabled.
- `services/src/main/java/org/keycloak/broker/jwtauthorizationgrant/JWTAuthorizationGrantConfig.java`
  defines provider settings for enabling the grant, assertion reuse, maximum
  assertion expiration, signature algorithm, access-token expiration limiting,
  and clock skew.
- `docs/documentation/upgrading/topics/changes/changes-26_7_0.adoc:362`
  documents removal of the experimental `token-exchange-external-internal:v2`
  feature.

Current Keycloak prerequisites are:

- A confidential client with the JWT Authorization Grant capability enabled.
- A JWT Authorization Grant identity provider for the external issuer.
- The client must be allowed to use that provider.
- Explicit allowed-audience configuration.
- A single assertion audience value.
- A `jti` claim.
- Short assertion lifetime; the provider default maximum is 300 seconds.
- Single-use assertions unless assertion reuse is explicitly configured.
- A pre-existing federated-identity link from the external subject to an
  internal user. The grant does not automatically create users or link
  accounts.

Subject behavior is confirmed from the local source: Keycloak resolves the
external assertion through a `BrokeredIdentityContext` and federated identity.
The resulting internal token may therefore have a different `sub` from the
external assertion. This is valid identity federation. PPE must not require
cross-issuer subject equality.

The Keycloak JWT Authorization Grant resolves federated users. It does not
establish that a `subject: client` external assertion can be mapped to a
Keycloak service account or OAuth client. Generic RFC 7523 support for a client
principal can still be implemented, but Keycloak interoperability for that mode
requires runtime verification and should not be claimed in the compatibility
profile until tested.

Actor behavior should remain unchanged: actor parameters belong to RFC 8693 and
must not be sent on the RFC 7523 import leg. Keycloak Standard Token Exchange
and Token Exchange Delegation remain responsible for `may_act`, actor
credentials, and delegation permissions on the second leg.

The two-realm integration scenario described under Testing has not been
executed. All Keycloak claims above are source-derived compatibility
requirements, not runtime-verified results.

## Findings Matrix

| Finding | Evidence | Validity | Feature impact | Owner | Blocking? | Recommended action |
| --- | --- | --- | --- | --- | --- | --- |
| Assertion audience may not identify the internal AS | RFC 7523 §3; RFC 10070 §4; Keycloak `JWTAuthorizationGrantType` audience checks | Confirmed | External JWT accepted as inbound PPE credential may still be ineligible as an import grant; Keycloak rejects multi-audience assertions | PPE, external issuer, and deployment configuration | Yes | Require explicit `authorization_server_audience` and a single-audience assertion for the Keycloak profile |
| External and internal subjects can differ | Keycloak federated identity resolution | Confirmed | The external-identity fallback can reject valid federation | Internal AS and PPE adaptation | Yes | Use the imported internal token as the existing subject-token comparison source and suppress the external fallback |
| `TokenKind::Jwt` alone does not prove bearer eligibility | `RawInboundToken` stores kind; `SecurityExtension` stores proof state; DPoP-off returns no binding despite `cnf` | Confirmed | A key-bound or confirmation-bearing JWT must not be used as a bearer grant | PPE | Yes | Require `TokenKind::Jwt`, no key binding, and no non-empty `cnf` claim |
| Assertion replay can fail on retry | Keycloak single-use assertion and `jti` behavior | Confirmed | Retry after an indeterminate import may be rejected | Internal AS | No | Preserve undelivered-only retry; do not cache the internal base token in v1 |
| Actor semantics must remain on leg two | RFC 8693 §2.1; current PPE form construction | Confirmed | Sending actor fields on RFC 7523 would be protocol mixing | PPE | Yes | Send actor parameters only on RFC 8693 leg |
| Import can amplify privileges | RFC 7523 grants authority based on assertion and AS policy | Confirmed | PPE policy authorizes delegation, but the internal AS still owns imported credential issuance | Deployment and internal AS | No | Document trust boundary; use Keycloak client scopes and policies; do not add a scope-mapping engine |
| `subject: client` may not interoperate with Keycloak | Keycloak grant resolves federated users | Requires runtime verification | Generic feature can support it, Keycloak profile cannot yet claim it | PPE and Keycloak deployment | No | Support both modes in code; mark Keycloak client-subject compatibility unverified |
| RFC 7523 response requires `token_type` | RFC 6749 §5.1; current `TokenExchangeResponse` omits it | Confirmed | Reusing the RFC 8693 response subset would accept nonconforming import responses | PPE | Yes | Add a dedicated `JwtBearerGrantResponse` with `access_token`, `token_type`, and optional `expires_in` |
| Sender-constrained JWTs are unsafe as bearer grants | RFC 7521 §3; `check_key_binding` DPoP-off behavior | Confirmed | DPoP, mTLS, and other confirmation-bearing JWTs must be rejected | PPE | Yes | Deny any non-empty `cnf` before the network call |
| Cache can mix direct and imported credentials if configuration changes | Existing key does not encode import mode | Partially confirmed | Potential collision if configuration changes while cache survives plugin construction | PPE | No | Encode subject-import mode in the cache-key domain |

### Independent Validation of Revised Hypotheses

#### Audience validation

Verdict: partially confirmed.

The same JWT can satisfy both PPE inbound authentication and the RFC 7523
grant only when its audience is deliberately issued for both consumers. PPE
validates `aud` against each trusted issuer's configured audience list
(`identity_jwt/config.rs:145` and `resolver.rs:1477`). RFC 7523 §3 requires the
assertion audience to identify the authorization server, and RFC 10070 §4
assigns the OAuth client responsibility for presenting the assertion to an
appropriate authorization server. The local RFC corpus does not include RFC
10070; that citation is based on the task-supplied RFC reference and is
cross-checked against RFC 7523 §3 and the local Keycloak implementation.

Current Keycloak does not accept the intuitive multi-audience solution.
`JWTAuthorizationGrantType` calls `validateTokenAudience(..., false)`
(`JWTAuthorizationGrantType.java:180`), and
`AbstractBaseJWTValidator.validateTokenAudience` rejects an assertion with more
than one audience when `multipleAudienceAllowed` is false
(`AbstractBaseJWTValidator.java:126`). Therefore:

```text
aud: ["praxis-api", "https://internal-idp.example.com/realms/internal"]
```

will be rejected by the current Keycloak JWT Authorization Grant path even if
PPE accepts it inbound.

The minimal v1 design is not to weaken either audience check or infer the
internal authorization-server identifier from a URL. Require an explicit import
audience, and require the selected JWT's `aud` to contain that configured value.
For the Keycloak compatibility profile, require exactly one audience value in
total. That same value may also appear in the inbound resolver's configured
audiences when a deployment intentionally uses one assertion for both PPE
authentication and internal import. `skip_audience_validation` must not be used
to make this integration work. Deployments that need distinct `praxis-api` and
internal-AS audiences require a separately issued assertion; assertion
acquisition remains outside v1.

#### Bearer eligibility

Verdict: confirmed.

`key_binding == None` is not sufficient. `check_key_binding` returns `Ok(None)`
immediately when `issuer.dpop.mode == DpopMode::Off`
(`identity_jwt/resolver.rs:1275`), before examining `cnf`. `SecurityExtension`
documents the distinction: `KeyBinding` means possession was proved, while a
token with `cnf` accepted without proof has no `KeyBinding`
(`ppe-core/src/extensions/security.rs:29`). RFC 7521 §3 treats the assertion
framework as a bearer-assertion mechanism rather than a holder-of-key
mechanism.

Eligibility must reject any selected JWT whose claims contain a non-empty `cnf`
member, regardless of the method named inside it. It should continue to reject
a verified `KeyBinding`, but that check alone is not enough.

#### Cache lookup

Verdict: confirmed.

`OAuthDelegator::handle` calls `cache_for` and then `cache.get_or_mint` before
invoking `exchange` (`delegator_oauth/delegator.rs:972`). If import eligibility
checks are placed inside `exchange`, every cache hit bypasses them. That is a
fail-open control-flow mistake, even though the existing cache key includes the
credential bytes and subject mode.

Eligibility must run in `handle` before `cache_for`, or `cache_for` must itself
return no cache when eligibility fails. Running it in `handle` is clearer: deny
first, then decide whether the delegation is cacheable.

#### Response validation

Verdict: confirmed.

Modeling `token_type` as a required JSON string is necessary but not
sufficient. RFC 6749 §5.1 requires a non-empty `access_token` and
`token_type`, and §7.1 says a client must not use an access token whose type it
does not understand. RFC 8693 §2.2 distinguishes `token_type`, which describes
how the token is used, from `issued_token_type`, which describes its
representation.

The import response should reject missing or empty `access_token`, missing or
empty `token_type`, and a `token_type` other than case-insensitive `Bearer`.
PPE only understands bearer internal base tokens for this path and will submit
that token to RFC 8693 as an access token.

#### Subject continuity

Verdict: partially confirmed; the earlier opaque-token blanket rejection is
rejected.

`validate_exchange_response` first tries to read `sub` from the actual
`subject_token` and only falls back to `caller_identity` when that token is not
a readable JWT (`delegator_oauth/delegator.rs:1341`). Once the imported internal
base token is leg two's `subject_token`, existing validation already compares
the final delegated JWT subject with the internal base-token subject.

The feature-specific defect is the fallback: for imported credentials, it is
the external caller identity and can compare an internal `sub` against an
external `sub`. The minimal change is to suppress that fallback on the imported
path. Then an internal-base JWT plus a final JWT uses the existing comparison;
an opaque internal base plus a readable final JWT reports
`subject_unverifiable`; an opaque internal base plus an opaque final token
preserves the existing behavior. There is no evidence that rejecting every
opaque internal base token before exchange is required for this feature.

## Alternatives

### 1. Optional `subject_import` in `delegator/oauth`

This adds an explicit first leg only when configured. It preserves all
existing subject modes when the field is absent and requires no core change.
Its costs are one new config type, one new response type, eligibility checks,
and additional tests.

This is recommended.

### 2. Make RFC 7523 the only grant

This saves one token-endpoint call but conflates subject import with
downstream attenuation. RFC 7523 has no standard `audience` parameter and
cannot represent the RFC 8693 actor semantics PPE already supports. It would
turn the internal AS's import policy into the downstream delegation policy.

Not recommended.

### 3. Extend the existing workload acquisition path generically

The existing `mint_base_token` shape is reusable as an implementation pattern,
but its semantics are client authentication. Reusing the same function or
request type without a clear protocol distinction risks sending
`client_assertion` parameters for an authorization grant. A separate function
and response type are clearer and only marginally more code.

Partially reuse the pattern, not the protocol abstraction.

### 4. Keep `subject_issuer`

`subject_issuer` was a Keycloak-specific hint for the removed experimental
provider. It is not an RFC 8693 parameter and does not solve the trust-domain
transition in a provider-neutral way.

Not recommended.

### 5. Have Praxis mint internal JWTs

This would make PPE an identity provider and move key distribution, subject
mapping, revocation, and claim issuance into the policy engine. It would
substantially expand scope and weaken the existing separation of identity
resolution, authorization, and credential acquisition.

Not recommended.

### 6. Pass the external token downstream

This does not meet the requirement that the downstream receive an internal
credential and depends on every downstream trusting the external issuer.

Not recommended.

## Recommended Design

### Configuration

Add this optional field to `OAuthDelegatorConfig`:

```yaml
subject_import:
  kind: jwt_bearer
```

Version one supports only `kind: jwt_bearer`. Unknown kinds must be rejected.
The following combinations must also be rejected:

- `subject_import` with `subject: caller_workload`
- `subject_import` with `subject: this_workload`

The intended modes are:

- `subject: user`
- `subject: client`

No import-leg `scope` is configured in version one. If a future authorization
server requires one, it should be an explicit fixed list, not route
permissions.

### Eligibility

Before the first network call, the delegator should:

1. Require `subject_import` to be configured and the subject mode to be
   supported.
2. Read the selected raw inbound token from
   `RawCredentialsExtension.inbound_tokens[TokenRole]`.
3. Require that token's `kind` to be `TokenKind::Jwt`.
4. Require its bytes to equal `DelegationPayload.bearer_token`, ensuring the
   selected credential is the credential being imported.
5. Require the corresponding `SecurityExtension.subject` or `.client` identity
   to have no key binding.
6. Require the JWT claims' `aud` to contain the configured
   `authorization_server_audience`; for the Keycloak compatibility profile,
   require exactly one audience value in total.
7. Reject a JWT whose claims contain a non-empty `cnf` member.
8. Deny if any check fails without sending the assertion.

All of these checks must run before delegated-token cache lookup. Placement
inside `exchange()` would bypass them on a cache hit.

This avoids extending `DelegationPayload` or adding a global verified-credential
abstraction. The existing resolver contract and extension metadata are
sufficient.

### Runtime Flow

Leg one sends:

```text
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
assertion=<external JWT>
```

It must not send:

- `subject_token`
- `subject_token_type`
- `actor_token`
- `actor_token_type`
- `client_assertion`
- `client_assertion_type`

The existing OAuth client authentication is used. The response is parsed as a
dedicated JWT Authorization Grant response and must contain `access_token` and
`token_type`.

Leg two sends the internal access token as:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<internal access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
audience=<route audience>
scope=<route permissions>
```

Actor parameters, if configured, are added only to leg two. The final response
continues through the existing RFC 8693 validation.

### Trust Boundaries

- The external issuer owns external JWT issuance, subject identity, and
  assertion audience.
- PPE owns inbound JWT verification, identity selection, authorization policy,
  eligibility checks, and delegation invocation.
- The internal authorization server owns assertion validation, federated
  subject mapping, imported-token issuance, scope policy, and token lifetime.
- The downstream resource owns enforcement of the final audience and
  credential constraints.

PPE must not weaken inbound JWT audience validation so that a `praxis-api`
credential can also be presented to an internal AS. The external issuer must
issue an assertion whose audience identifies the internal authorization server.

### Subject Continuity

For imported credentials, strict response validation should compare:

```text
final delegated JWT sub == internal base token sub
```

If the internal base token is a JWT, its claims can be read locally after the
trusted token-endpoint response, and existing `validate_exchange_response`
already compares the final delegated JWT subject with its `sub`. The imported
path should suppress the fallback to the external caller identity. If the
internal base token is opaque and the final token is a readable JWT, existing
validation reports `subject_unverifiable`. If both are opaque, preserve the
existing strict-validation behavior rather than adding a feature-specific
blanket rejection. If strict validation is disabled, preserve the existing
explicit opt-out.

External-to-internal subject equality is neither required nor sufficient. The
internal AS is responsible for mapping the external federated identity to the
internal principal.

### Response Validation

Add a dedicated response type:

```rust
struct JwtBearerGrantResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<i64>,
}
```

After deserialization, reject empty `access_token`, empty `token_type`, and a
`token_type` other than case-insensitive `Bearer`. RFC 6749 §7.1 forbids using
an access-token type the client does not understand.

Do not refactor the existing RFC 8693 response type. The second leg should
derive its subject token type from the acquisition mechanism and use the
access-token type URN, not the user-configured inbound `subject_token_type`.

### Cache Behavior

The final delegated-token cache remains the only cache. A cache hit skips both
legs. A miss runs import and exchange as one uncached mint operation.

Add subject-import mode to the cache-key domain so imported and direct-exchange
entries cannot collide. The external assertion bytes already participate as the
credential anchor, and the existing key includes client, endpoint, subject,
actor, audience, and scope isolation.

Do not cache the internal base token in version one. That would require
assertion replay, internal-token expiry, failure reconciliation, and policy
reload semantics beyond this feature.

### Failure Semantics

- Eligibility failure denies before any network call.
- Import transport failure, timeout, non-success response, or malformed response
  denies the whole delegation.
- Exchange failure after successful import also denies the whole delegation.
- Each leg records a separate mint effect with a distinct leg label.
- Existing `undelivered_only` retry behavior is preserved.
- OAuth error bodies and submitted assertions must not be echoed into violation
  details.

## Test Strategy

### Backward Compatibility

- Absence of `subject_import` leaves all existing request forms unchanged.
- Existing `subject: user`, `client`, `caller_workload`, and `this_workload`
  tests continue to pass.
- Actor behavior outside the import path is unchanged.
- Existing configuration remains valid.

### Configuration

- `subject_import.kind: jwt_bearer` is accepted.
- Unknown import kinds are rejected.
- Missing `authorization_server_audience` is rejected.
- Import with `caller_workload` and `this_workload` is rejected.
- Import with `user` and `client` is accepted.

### Protocol

- Leg one sends the JWT bearer grant type and `assertion`.
- Leg one sends no RFC 8693 subject or actor parameters and no client-assertion
  parameters.
- Leg two sends the internal access token as `subject_token` with the
  access-token type URN.
- Actor parameters appear only on leg two.
- Target audience and route scopes appear only on leg two.

### Security

- Missing selected raw credential denies before network.
- Opaque selected credential denies before network.
- Key-bound selected identity denies before network.
- A selected JWT containing any non-empty `cnf` member denies before network,
  even when DPoP is disabled and `key_binding` is therefore `None`.
- Mismatch between selected raw credential and payload bearer denies before
  network.
- An assertion whose audience does not match the configured
  `authorization_server_audience` denies before network.
- A multi-audience assertion denies under the Keycloak compatibility profile.
- Import response missing `token_type` or `access_token` denies.
- Import response with an empty value or a token type other than
  case-insensitive `Bearer` denies.
- Final subject is compared to the internal base token subject.
- The external caller identity is not used as the imported-path subject
  fallback.
- Import eligibility runs before cache lookup and therefore also runs on cache
  hits.
- Error responses do not expose assertions or client secrets.
- Direct and imported cache entries do not collide.

### Operations

- Import and exchange produce separate effects with leg labels.
- Transport failure, timeout, OAuth rejection, malformed JSON, and partial
  success each deny appropriately.
- Undelivered-only retry is preserved.
- Concurrent identical requests coalesce when cache is enabled.
- Cache hits skip both network legs.

### Real Keycloak Interoperability

A small two-realm or two-authorization-domain test should be added:

1. External realm issues a short-lived JWT with a single audience identifying
   the internal authorization server and a unique `jti`.
2. Internal realm configures a JWT Authorization Grant identity provider,
   allowed audience, confidential client, and a pre-linked federated user.
3. PPE verifies the external JWT, applies policy, imports the subject, and
   exchanges the internal access token.
4. The final token is used at a protected downstream resource.
5. Replay and subject-mapping behavior are exercised.

This scenario is an unexecuted test plan. Mocked HTTP tests are necessary but
not sufficient to claim Keycloak compatibility.

## Minimal Implementation Plan

Files to change:

- `crates/builtins/src/plugins/delegator_oauth/config.rs`
  - Add `SubjectImportConfig`.
  - Validate kind, required import audience, and supported subject-mode
    combinations.
- `crates/builtins/src/plugins/delegator_oauth/delegator.rs`
  - Add RFC 7523 import leg.
  - Add `JwtBearerGrantResponse`.
  - Add selected-credential, audience, and `cnf` eligibility checks before
    delegated-token cache lookup.
  - Adapt the imported-path subject-identity fallback.
  - Add leg-labeled effects.
- `crates/builtins/src/plugins/delegator_oauth/cache/key.rs`
  - Encode subject-import mode.
- `crates/builtins/tests/oauth/oauth_e2e.rs`
  - Add configuration, protocol, security, failure, cache, and actor tests.
- `docs/content/apl/delegation.md`
- `docs/content/guides/identity-delegation.md`
  - Document configuration, prerequisites, trust boundaries, and the Keycloak
    compatibility profile.

No Praxis Core change is required.

Suggested reviewable commits:

1. Configuration and eligibility checks.
2. RFC 7523 import leg and response parsing.
3. RFC 8693 integration, subject continuity adaptation, and cache isolation.
4. Tests and documentation.

## Upstream Blocker Register

No existing upstream defects require remediation within the scope of this
feature.

Two current PPE limitations are feature-specific implementation prerequisites,
not reasons to expand scope:

| Limitation | Evidence | Why it blocks this feature | Minimal resolution | Separation strategy |
| --- | --- | --- | --- | --- |
| RFC 8693 response subset omits `token_type` | `TokenExchangeResponse` at `delegator.rs:574` | RFC 7523 successful responses require `token_type` | Dedicated `JwtBearerGrantResponse` | Include in the RFC 7523 import-leg commit |
| Imported path can fall back from the internal subject token to the external caller identity | `validate_exchange_response` at `delegator.rs:1341` | Imported internal subject may legitimately differ from external subject | Preserve subject-token-first comparison and suppress the external fallback | Include in the exchange-integration commit |

Existing client authentication, DPoP, mTLS, refresh-token, actor-federation, and
cache-lifecycle limitations are not blockers and must not be fixed as part of
this feature.

## Known Limitations

- Version one does not acquire assertions from an upstream authorization
  mechanism; the inbound JWT must already be eligible for the internal AS.
- Version one does not support import-leg scopes.
- Version one does not cache internal base tokens.
- Version one does not implement DPoP, mTLS, refresh tokens, renewable
  sessions, or a general identity-mapping subsystem.
- Keycloak `subject: client` interoperability is unverified.
- The real Keycloak integration scenario is a plan, not an executed result.
