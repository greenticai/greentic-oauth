//! OAuth session lifecycle inside the WASM component.
//!
//! Session data (state token, PKCE verifier, conversation_id) is persisted
//! via the `greentic:state/state-store@1.0.0` WIT capability. This is the
//! same state store used by the bundle's `state-memory` pack, so writes
//! from `handle_resolve_card` are visible to reads in `handle_ingest_http`
//! when both invocations run against the same bundle tenant.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::RuntimeError;

pub const SESSION_TTL_SECS: i64 = 600;

#[derive(Debug, Clone)]
pub struct CreateInput {
    pub tenant: String,
    pub team: Option<String>,
    pub provider_id: String,
    pub provider_pack_id: String,
    pub conversation_id: String,
}

#[derive(Debug, Clone)]
pub struct SessionTicket {
    pub state_token: String,
    #[allow(dead_code)] // returned to caller for future use; today caller reads state_token + code_challenge
    pub code_verifier: String,
    pub code_challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRecord {
    pub state_token: String,
    pub code_verifier: String,
    pub provider_id: String,
    pub provider_pack_id: String,
    pub tenant: String,
    pub team: Option<String>,
    pub conversation_id: String,
    pub created_at_unix_ms: i64,
}

/// Abstraction over the state-store WIT so the module can be unit-tested
/// without WASM. The production `WitStateStore` impl delegates to the WIT
/// bindings (added in a later task); tests use an in-memory `HashMap` impl.
pub trait StateStore {
    fn read(&self, key: &str, tenant: &str, team: Option<&str>) -> Result<Option<Vec<u8>>, String>;
    fn write(&self, key: &str, bytes: &[u8], tenant: &str, team: Option<&str>) -> Result<(), String>;
    fn delete(&self, key: &str, tenant: &str, team: Option<&str>) -> Result<(), String>;
}

fn session_key(state_token: &str) -> String {
    format!("oauth-session:{state_token}")
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn random_url_safe(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

pub fn create_session(
    store: &dyn StateStore,
    input: CreateInput,
) -> Result<SessionTicket, RuntimeError> {
    let state_token = random_url_safe(32);
    let code_verifier = random_url_safe(64);
    let code_challenge = pkce_challenge_s256(&code_verifier);

    let record = SessionRecord {
        state_token: state_token.clone(),
        code_verifier: code_verifier.clone(),
        provider_id: input.provider_id,
        provider_pack_id: input.provider_pack_id,
        tenant: input.tenant.clone(),
        team: input.team.clone(),
        conversation_id: input.conversation_id,
        created_at_unix_ms: now_unix_ms(),
    };

    let bytes = serde_json::to_vec(&record)
        .map_err(|err| RuntimeError::InvalidInput(format!("serialize session: {err}")))?;

    store
        .write(&session_key(&state_token), &bytes, &input.tenant, input.team.as_deref())
        .map_err(|err| RuntimeError::InvalidInput(format!("state-store write: {err}")))?;

    Ok(SessionTicket {
        state_token,
        code_verifier,
        code_challenge,
    })
}

pub fn consume_session(
    store: &dyn StateStore,
    state_token: &str,
    tenant: &str,
    team: Option<&str>,
) -> Result<SessionRecord, RuntimeError> {
    let key = session_key(state_token);
    let bytes = store
        .read(&key, tenant, team)
        .map_err(|err| RuntimeError::InvalidInput(format!("state-store read: {err}")))?
        .ok_or_else(|| {
            RuntimeError::InvalidInput(format!("session not found: {state_token}"))
        })?;

    let record: SessionRecord = serde_json::from_slice(&bytes)
        .map_err(|err| RuntimeError::InvalidInput(format!("parse session: {err}")))?;

    // Check expiry
    let age_ms = now_unix_ms() - record.created_at_unix_ms;
    if age_ms > SESSION_TTL_SECS * 1000 {
        // Best-effort delete of the stale record
        let _ = store.delete(&key, tenant, team);
        return Err(RuntimeError::InvalidInput(format!(
            "session expired ({state_token})"
        )));
    }

    // Best-effort delete of the consumed record
    let _ = store.delete(&key, tenant, team);

    Ok(record)
}

#[cfg(test)]
pub mod test_support {
    //! Test-only in-memory StateStore impl. Exposed via `pub` so other modules
    //! in this crate can reuse it in their own unit tests.
    use super::StateStore;
    use std::cell::RefCell;
    use std::collections::HashMap;

    pub struct InMemoryStore {
        pub data: RefCell<HashMap<String, Vec<u8>>>,
    }

    impl InMemoryStore {
        pub fn new() -> Self {
            Self {
                data: RefCell::new(HashMap::new()),
            }
        }
    }

    impl Default for InMemoryStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl StateStore for InMemoryStore {
        fn read(&self, key: &str, _tenant: &str, _team: Option<&str>) -> Result<Option<Vec<u8>>, String> {
            Ok(self.data.borrow().get(key).cloned())
        }
        fn write(&self, key: &str, bytes: &[u8], _tenant: &str, _team: Option<&str>) -> Result<(), String> {
            self.data.borrow_mut().insert(key.to_string(), bytes.to_vec());
            Ok(())
        }
        fn delete(&self, key: &str, _tenant: &str, _team: Option<&str>) -> Result<(), String> {
            self.data.borrow_mut().remove(key);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_support::InMemoryStore;

    fn sample_input() -> CreateInput {
        CreateInput {
            tenant: "demo".to_string(),
            team: Some("default".to_string()),
            provider_id: "github".to_string(),
            provider_pack_id: "oauth-oidc-generic".to_string(),
            conversation_id: "conv-1".to_string(),
        }
    }

    #[test]
    fn create_session_writes_to_state_store_with_random_values() {
        let store = InMemoryStore::new();
        let ticket = create_session(&store, sample_input()).unwrap();
        assert!(!ticket.state_token.is_empty());
        assert!(!ticket.code_verifier.is_empty());
        assert!(!ticket.code_challenge.is_empty());
        let key = format!("oauth-session:{}", ticket.state_token);
        assert!(store.data.borrow().contains_key(&key));
    }

    #[test]
    fn create_session_returns_unique_state_tokens() {
        let store = InMemoryStore::new();
        let a = create_session(&store, sample_input()).unwrap();
        let b = create_session(&store, sample_input()).unwrap();
        assert_ne!(a.state_token, b.state_token);
        assert_ne!(a.code_verifier, b.code_verifier);
    }

    #[test]
    fn consume_session_returns_record_and_deletes() {
        let store = InMemoryStore::new();
        let ticket = create_session(&store, sample_input()).unwrap();
        let record = consume_session(&store, &ticket.state_token, "demo", Some("default")).unwrap();
        assert_eq!(record.provider_id, "github");
        assert_eq!(record.conversation_id, "conv-1");
        assert_eq!(record.code_verifier, ticket.code_verifier);
        let key = format!("oauth-session:{}", ticket.state_token);
        assert!(!store.data.borrow().contains_key(&key));
    }

    #[test]
    fn consume_session_errors_on_unknown_state_token() {
        let store = InMemoryStore::new();
        let err = consume_session(&store, "nonexistent", "demo", None).unwrap_err();
        match err {
            RuntimeError::InvalidInput(msg) => assert!(msg.contains("session not found")),
            _ => panic!("expected InvalidInput"),
        }
    }

    #[test]
    fn consume_session_errors_on_expired_session() {
        let store = InMemoryStore::new();
        let ticket = create_session(&store, sample_input()).unwrap();
        // Mutate the stored record to backdate it
        let key = format!("oauth-session:{}", ticket.state_token);
        let bytes = store.data.borrow().get(&key).unwrap().clone();
        let mut record: SessionRecord = serde_json::from_slice(&bytes).unwrap();
        record.created_at_unix_ms = 0;
        store
            .data
            .borrow_mut()
            .insert(key, serde_json::to_vec(&record).unwrap());
        let err = consume_session(&store, &ticket.state_token, "demo", Some("default")).unwrap_err();
        match err {
            RuntimeError::InvalidInput(msg) => assert!(msg.contains("expired")),
            _ => panic!("expected InvalidInput"),
        }
    }

    #[test]
    fn code_challenge_is_base64url_sha256_of_verifier() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let actual = pkce_challenge_s256(verifier);
        assert_eq!(actual, expected);
    }
}
