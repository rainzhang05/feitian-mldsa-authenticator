//! Skeleton Trussed application integrating the ML-DSA signature scheme.
//!
//! This module outlines how a FIDO2 authenticator could incorporate
//! ML-DSA-44/65/87 into credential creation and assertion.  It does not
//! implement a full CTAP2 state machine or the WebAuthn attestation
//! protocol; instead it sketches the key data structures and helper
//! functions needed to plug ML-DSA into an existing Trussed runner.
//!
//! A real authenticator must:
//!
//! * Implement the CTAP2 commands `get_info`, `make_credential` and
//!   `get_assertion`, marshalling and unmarshalling CBOR requests.
//! * Persist credentials in a secure store.
//! * Handle user verification (PIN, biometric or presence) as per the
//!   requirements of FIDO2.
//! * Advertise the supported COSE algorithm identifiers in the response
//!   to `get_info`.  Draft ML-DSA WebAuthn integration assigns temporary
//!   IDs -48, -49 and -50 for ML-DSA-44, ML-DSA-65 and ML-DSA-87
//!   respectively【980082228157822†L243-L256】.
//!
//! The functions in this file demonstrate how to:
//!
//! * Map a COSE algorithm ID to an ML-DSA parameter set.
//! * Generate a keypair via the `trussed-mldsa` wrapper.
//! * Construct a COSE_Key for the public key using CBOR encoding.
//! * Sign a challenge using the selected parameter set.
//!
use ciborium::ser::into_writer;
use ciborium::value::{Integer, Value};
use trussed_mldsa::{keypair, sign, ParamSet, PublicKey, SecretKey};

/// Enumeration of COSE algorithm identifiers for ML-DSA.  These values
/// follow the draft COSE registration; they are negative because COSE
/// reserves negative numbers for signature algorithms.
///
/// * -48 -> ML-DSA-44
/// * -49 -> ML-DSA-65
/// * -50 -> ML-DSA-87
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CoseAlg {
    MLDSA44 = -48,
    MLDSA65 = -49,
    MLDSA87 = -50,
}

impl TryFrom<i32> for CoseAlg {
    type Error = ();
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            -48 => Ok(CoseAlg::MLDSA44),
            -49 => Ok(CoseAlg::MLDSA65),
            -50 => Ok(CoseAlg::MLDSA87),
            _ => Err(()),
        }
    }
}

/// Map a COSE algorithm identifier to the corresponding ML-DSA parameter set.
pub fn paramset_from_alg(alg: CoseAlg) -> ParamSet {
    match alg {
        CoseAlg::MLDSA44 => ParamSet::MLDsa44,
        CoseAlg::MLDSA65 => ParamSet::MLDsa65,
        CoseAlg::MLDSA87 => ParamSet::MLDsa87,
    }
}

/// Generate a COSE_Key for a given public key and parameter set.
///
/// The returned vector contains the CBOR encoding of a map with the
/// standard fields:
///
/// * **1 (kty)**: key type; here we reuse OKP (1) as a placeholder.
/// * **3 (alg)**: the COSE algorithm identifier (-48/-49/-50).
/// * **-1 (crv)**: a curve identifier equal to 44, 65 or 87, matching the
///   parameter set.
/// * **-2 (x)**: the raw public key bytes.
///
/// In a production implementation the key type and labels should match the
/// values assigned by the IANA COSE registry once ML-DSA is finalised.
pub fn cose_public_key(ps: ParamSet, pk: &PublicKey) -> Vec<u8> {
    let (alg_id, curve_id) = match ps {
        ParamSet::MLDsa44 => (-48, 44),
        ParamSet::MLDsa65 => (-49, 65),
        ParamSet::MLDsa87 => (-50, 87),
    };
    // Build a CBOR map {1:1, 3:alg_id, -1:curve_id, -2:pk_bytes}
    let mut m = std::collections::BTreeMap::new();
    m.insert(Value::Integer(Integer::from(1)), Value::Integer(Integer::from(1))); // kty = OKP
    m.insert(Value::Integer(Integer::from(3)), Value::Integer(Integer::from(alg_id)));
    m.insert(Value::Integer(Integer::from(-1)), Value::Integer(Integer::from(curve_id)));
    m.insert(Value::Integer(Integer::from(-2)), Value::Bytes(pk.0.clone()));
    let mut out = Vec::new();
    into_writer(&Value::Map(m), &mut out).expect("CBOR encoding failed");
    out
}

/// Generate a new ML-DSA credential.  Returns the COSE_Key and a secret key
/// wrapper.  In a real authenticator you would store the secret key in
/// secure persistent storage and return only the credential ID and public
/// key to the client.
pub fn create_credential(alg: CoseAlg) -> (Vec<u8>, SecretKey) {
    let ps = paramset_from_alg(alg);
    let (pk, sk) = keypair(ps);
    let cose = cose_public_key(ps, &pk);
    (cose, sk)
}

/// Produce an ML-DSA signature over `auth_data || client_data_hash` using
/// the provided secret key.  Returns the raw signature bytes.
pub fn sign_challenge(alg: CoseAlg, sk: &SecretKey, auth_data: &[u8], client_data_hash: &[u8]) -> Vec<u8> {
    let ps = paramset_from_alg(alg);
    let mut msg = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    msg.extend_from_slice(auth_data);
    msg.extend_from_slice(client_data_hash);
    sign(ps, sk, &msg)
}

// Additional structs and functions would be defined here to manage
// credential records, persist secrets via Trussed storage, and
// implement the CTAP2 command handlers.  See the README for links
// explaining how to integrate this crate into a runner.