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
#[allow(deprecated)]
use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use ciborium::ser::into_writer;
use ciborium::value::{Integer, Value};
use hkdf::Hkdf;
use sha2::Sha256;
use trussed_mldsa::{keypair, sign, ParamSet, PublicKey, SecretKey};
use zeroize::Zeroize;

pub mod ctap;

/// Identifier advertised in `authenticatorGetInfo` for the PQC PIN/UV protocol.
pub const PIN_UV_AUTH_PROTOCOL_PQC: u8 = 101;

/// Session keys derived from an ML-KEM shared secret and the transcript hash.
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct PinUvSessionKeys {
    pub encryption_key: [u8; 32],
    pub auth_key: [u8; 32],
}

/// Derive the AES-256-GCM encryption key and the 32-byte HMAC key used for
/// client PIN handling.  The HKDF salt binds the keys to the transcript hash.
pub fn derive_pin_uv_session_keys(
    shared_secret: &[u8],
    transcript_hash: &[u8],
) -> PinUvSessionKeys {
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret);
    let mut okm = [0u8; 64];
    hkdf.expand(b"FIDO2-PQC-PIN-KEYS", &mut okm)
        .expect("HKDF expand must not fail for valid length");
    let mut encryption_key = [0u8; 32];
    let mut auth_key = [0u8; 32];
    encryption_key.copy_from_slice(&okm[..32]);
    auth_key.copy_from_slice(&okm[32..]);
    okm.zeroize();
    PinUvSessionKeys {
        encryption_key,
        auth_key,
    }
}

/// Encrypt PIN data using AES-256-GCM.  The transcript hash should be supplied
/// as AAD to bind the ciphertext to the protocol run.
#[allow(deprecated)]
pub fn encrypt_pin_block(
    keys: &PinUvSessionKeys,
    nonce: &[u8; 12],
    plaintext: &[u8],
    transcript_hash: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(&keys.encryption_key).expect("invalid AES key length");
    let nonce_ga = GenericArray::clone_from_slice(nonce);
    cipher
        .encrypt(
            &nonce_ga,
            Payload {
                msg: plaintext,
                aad: transcript_hash,
            },
        )
        .expect("encryption should not fail for valid parameters")
}

/// Decrypt the PIN block using AES-256-GCM and the previously derived keys.
#[allow(deprecated)]
pub fn decrypt_pin_block(
    keys: &PinUvSessionKeys,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(&keys.encryption_key).expect("invalid AES key length");
    let nonce_ga = GenericArray::clone_from_slice(nonce);
    cipher.decrypt(
        &nonce_ga,
        Payload {
            msg: ciphertext,
            aad: transcript_hash,
        },
    )
}

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
    let mut m = Vec::with_capacity(4);
    m.push((
        Value::Integer(Integer::from(1)),
        Value::Integer(Integer::from(1)),
    ));
    m.push((
        Value::Integer(Integer::from(3)),
        Value::Integer(Integer::from(alg_id)),
    ));
    m.push((
        Value::Integer(Integer::from(-1)),
        Value::Integer(Integer::from(curve_id)),
    ));
    m.push((
        Value::Integer(Integer::from(-2)),
        Value::Bytes(pk.0.clone()),
    ));
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
pub fn sign_challenge(
    alg: CoseAlg,
    sk: &SecretKey,
    auth_data: &[u8],
    client_data_hash: &[u8],
) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Integer;
    use trussed_mldsa::verify;
    use trussed_mlkem::{self, ParamSet as KemParamSet};

    #[test]
    fn mldsa_roundtrip_signatures() {
        for alg in [CoseAlg::MLDSA44, CoseAlg::MLDSA65, CoseAlg::MLDSA87] {
            let (public_key_cbor, secret_key) = create_credential(alg);
            assert!(!public_key_cbor.is_empty());
            let auth_data = b"auth_data";
            let client_hash = b"client_data_hash";
            let signature = sign_challenge(alg, &secret_key, auth_data, client_hash);
            let ps = paramset_from_alg(alg);
            let message: Vec<u8> = auth_data.iter().chain(client_hash).cloned().collect();
            let pk = PublicKey(public_key_from_cose(&public_key_cbor));
            assert!(verify(ps, &pk, &message, &signature));
        }
    }

    fn public_key_from_cose(cbor: &[u8]) -> Vec<u8> {
        let value: ciborium::value::Value = ciborium::de::from_reader(cbor).expect("valid CBOR");
        if let ciborium::value::Value::Map(map) = value {
            for (k, v) in map {
                if k == ciborium::value::Value::Integer(Integer::from(-2)) {
                    if let ciborium::value::Value::Bytes(bytes) = v {
                        return bytes;
                    }
                }
            }
        }
        panic!("COSE key missing public key bytes");
    }

    #[test]
    fn mlkem_pin_protocol_roundtrip() {
        let (pk, sk) = trussed_mlkem::keypair(KemParamSet::MLKem512);
        let (ciphertext, shared_secret_client) =
            trussed_mlkem::encapsulate(KemParamSet::MLKem512, &pk);
        let shared_secret_auth =
            trussed_mlkem::decapsulate(KemParamSet::MLKem512, &sk, &ciphertext);
        let transcript_hash = b"transcript";
        let client_keys = derive_pin_uv_session_keys(&shared_secret_client.0, transcript_hash);
        let auth_keys = derive_pin_uv_session_keys(&shared_secret_auth.0, transcript_hash);
        let nonce = [0u8; 12];
        let plaintext = b"PIN data";
        let ciphertext = encrypt_pin_block(&client_keys, &nonce, plaintext, transcript_hash);
        let decrypted = decrypt_pin_block(&auth_keys, &nonce, &ciphertext, transcript_hash)
            .expect("decryption should succeed");
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
