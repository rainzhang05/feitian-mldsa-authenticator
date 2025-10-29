use crate::{
    cose_akp_key_map, cose_alg_for_kem_param_set, create_credential, credential_secret_from_bytes,
    decrypt_classic_pin_block, decrypt_pqc_pin_block, derive_classic_pin_uv_session_keys,
    derive_pqc_pin_uv_session_keys, encrypt_classic_pin_block, encrypt_pqc_pin_block,
    sign_challenge, ClassicPinProtocol, CoseAlg, PinUvSessionKeys, PIN_UV_AUTH_PROTOCOL_PQC,
};

use aes::Aes256;
use cbc::{
    cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Decryptor, Encryptor,
};
use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use ctaphid_app::{App, Command, Error};
use hmac::{Hmac, Mac};
use p256::{
    ecdh::diffie_hellman,
    ecdsa::{signature::Signer, Signature as P256EcdsaSignature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    EncodedPoint, PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};
use trussed::syscall;
#[cfg(not(test))]
use trussed::types::PathBuf;
#[cfg(not(test))]
use trussed::{
    try_syscall,
    types::{Location, Message},
};
use trussed_mlkem::{self, Ciphertext, ParamSet as KemParamSet, SecretKey as KemSecretKey};
use zeroize::Zeroize;

use std::{cmp::Ordering, collections::VecDeque};

fn canonical_fallback_cmp(left: &Value, right: &Value) -> Ordering {
    let mut left_bytes = Vec::new();
    into_writer(left, &mut left_bytes).expect("serialize left key for canonical ordering");
    let mut right_bytes = Vec::new();
    into_writer(right, &mut right_bytes).expect("serialize right key for canonical ordering");
    match left_bytes.len().cmp(&right_bytes.len()) {
        Ordering::Equal => left_bytes.cmp(&right_bytes),
        other => other,
    }
}

fn canonical_key_cmp(left: &Value, right: &Value) -> Ordering {
    use Value::{Integer as IntValue, Text};

    match (left, right) {
        (IntValue(left_int), IntValue(right_int)) => left_int.canonical_cmp(right_int),
        (IntValue(_), Text(_)) => Ordering::Less,
        (Text(_), IntValue(_)) => Ordering::Greater,
        (Text(left_text), Text(right_text)) => match left_text.len().cmp(&right_text.len()) {
            Ordering::Equal => left_text.cmp(right_text),
            other => other,
        },
        (Value::Bytes(left_bytes), Value::Bytes(right_bytes)) => {
            match left_bytes.len().cmp(&right_bytes.len()) {
                Ordering::Equal => left_bytes.cmp(right_bytes),
                other => other,
            }
        }
        (Value::Bool(left_bool), Value::Bool(right_bool)) => left_bool.cmp(right_bool),
        _ => canonical_fallback_cmp(left, right),
    }
}

fn canonical_sort(entries: &mut Vec<(Value, Value)>) {
    entries.sort_by(|(left_key, _), (right_key, _)| canonical_key_cmp(left_key, right_key));
}

fn canonical_map(mut entries: Vec<(Value, Value)>) -> Value {
    canonical_sort(&mut entries);
    Value::Map(entries)
}

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

fn encrypt_shared_secret(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, u8> {
    if plaintext.len() % 16 != 0 {
        return Err(CTAP1_ERR_INVALID_PARAMETER);
    }
    let cipher =
        Aes256CbcEnc::new_from_slices(key, &[0u8; 16]).map_err(|_| CTAP2_ERR_PROCESSING)?;
    Ok(cipher.encrypt_padded_vec_mut::<NoPadding>(plaintext))
}

fn decrypt_shared_secret(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, u8> {
    if ciphertext.len() % 16 != 0 {
        return Err(CTAP1_ERR_INVALID_PARAMETER);
    }
    let mut buffer = ciphertext.to_vec();
    let cipher =
        Aes256CbcDec::new_from_slices(key, &[0u8; 16]).map_err(|_| CTAP2_ERR_PROCESSING)?;
    let plaintext = cipher
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| CTAP1_ERR_INVALID_PARAMETER)?;
    Ok(plaintext.to_vec())
}

const CTAP_CMD_MAKE_CREDENTIAL: u8 = 0x01;
const CTAP_CMD_GET_ASSERTION: u8 = 0x02;
const CTAP_CMD_GET_INFO: u8 = 0x04;
const CTAP_CMD_CLIENT_PIN: u8 = 0x06;
const CTAP_CMD_GET_NEXT_ASSERTION: u8 = 0x08;
const CTAP_CMD_CREDENTIAL_MANAGEMENT: u8 = 0x0A;

const CTAP2_OK: u8 = 0x00;
const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const CTAP2_ERR_INVALID_OPTION: u8 = 0x2C;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
const CTAP1_ERR_INVALID_PARAMETER: u8 = 0x2D;
const CTAP2_ERR_NOT_ALLOWED: u8 = 0x30;
const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
const CTAP2_ERR_PIN_BLOCKED: u8 = 0x32;
const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
const CTAP2_ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
const CTAP2_ERR_PROCESSING: u8 = 0x21;
const CTAP2_ERR_PUAT_REQUIRED: u8 = 0x36;
const CTAP2_ERR_UNAUTHORIZED_PERMISSION: u8 = 0x40;

const MAX_PIN_RETRIES: u8 = 8;
const MAX_PIN_FAILURES_BEFORE_BLOCK: u8 = 3;

type HmacSha256 = Hmac<Sha256>;

const COSE_ALG_ES256: i32 = -7;

#[cfg(not(test))]
const CREDENTIAL_STORE_PATH: &str = "credentials.cbor";
#[cfg(not(test))]
const ATTESTATION_STORE_PATH: &str = "attestation.cbor";
const PIN_UV_AUTH_PROTOCOL_CLASSIC_V1: i32 = 1;
const PIN_UV_AUTH_PROTOCOL_CLASSIC_V2: i32 = 2;
const PIN_UV_AUTH_PROTOCOL_CLASSIC: i32 = PIN_UV_AUTH_PROTOCOL_CLASSIC_V2;
const SUPPORTED_PIN_UV_PROTOCOLS: [i32; 3] = [
    PIN_UV_AUTH_PROTOCOL_PQC as i32,
    PIN_UV_AUTH_PROTOCOL_CLASSIC_V2,
    PIN_UV_AUTH_PROTOCOL_CLASSIC_V1,
];

const PIN_PERMISSION_MC: u8 = 0x01;
const PIN_PERMISSION_GA: u8 = 0x02;
const PIN_PERMISSION_CM: u8 = 0x04;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredCredential {
    rp_id: String,
    user_id: Vec<u8>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    alg: i32,
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    #[serde(default)]
    cred_random_with_uv: Option<Vec<u8>>,
    #[serde(default)]
    cred_random_without_uv: Option<Vec<u8>>,
    #[serde(default)]
    cred_protect: Option<u8>,
    sign_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAttestation {
    private_key: Vec<u8>,
    certificate_chain: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct PinState {
    pin_hash: Option<[u8; 16]>,
    pin_retries: u8,
    consecutive_failures: u8,
    pin_auth_blocked: bool,
    pin_uv_auth_token: Option<[u8; 32]>,
    pin_uv_auth_permissions: u8,
    pin_uv_auth_rp_id: Option<String>,
    pin_uv_auth_rp_provided: bool,
}

impl PinState {
    const MIN_PIN_LENGTH: usize = 4;

    fn new() -> Self {
        Self {
            pin_hash: None,
            pin_retries: MAX_PIN_RETRIES,
            consecutive_failures: 0,
            pin_auth_blocked: false,
            pin_uv_auth_token: None,
            pin_uv_auth_permissions: 0,
            pin_uv_auth_rp_id: None,
            pin_uv_auth_rp_provided: false,
        }
    }

    fn is_set(&self) -> bool {
        self.pin_hash.is_some()
    }

    fn set_pin(&mut self, hash: [u8; 16]) {
        self.pin_hash = Some(hash);
        self.pin_retries = MAX_PIN_RETRIES;
        self.consecutive_failures = 0;
        self.clear_pin_uv_auth_token();
    }

    fn retries(&self) -> u8 {
        self.pin_retries
    }

    fn needs_power_cycle(&self) -> bool {
        self.pin_auth_blocked
    }

    fn verify_pin_hash(&mut self, candidate: &[u8; 16]) -> Result<(), u8> {
        let Some(stored) = self.pin_hash else {
            return Err(CTAP2_ERR_PIN_NOT_SET);
        };
        if self.pin_auth_blocked {
            return Err(CTAP2_ERR_PIN_AUTH_BLOCKED);
        }
        if stored == *candidate {
            self.pin_retries = MAX_PIN_RETRIES;
            self.consecutive_failures = 0;
            Ok(())
        } else {
            if self.pin_retries > 0 {
                self.pin_retries -= 1;
            }
            if self.pin_retries == 0 {
                return Err(CTAP2_ERR_PIN_BLOCKED);
            }
            self.consecutive_failures = self
                .consecutive_failures
                .saturating_add(1)
                .min(MAX_PIN_FAILURES_BEFORE_BLOCK);
            if self.consecutive_failures >= MAX_PIN_FAILURES_BEFORE_BLOCK {
                self.pin_auth_blocked = true;
                Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
            } else {
                Err(CTAP2_ERR_PIN_INVALID)
            }
        }
    }

    fn clear_pin_uv_auth_token(&mut self) {
        if let Some(mut token) = self.pin_uv_auth_token.take() {
            token.zeroize();
        }
        self.pin_uv_auth_permissions = 0;
        self.pin_uv_auth_rp_provided = false;
        if let Some(mut rp_id) = self.pin_uv_auth_rp_id.take() {
            rp_id.zeroize();
        }
    }

    fn set_pin_uv_auth_token(&mut self, token: [u8; 32], permissions: u8, rp_id: Option<String>) {
        self.clear_pin_uv_auth_token();
        self.pin_uv_auth_token = Some(token);
        self.pin_uv_auth_permissions = permissions;
        self.pin_uv_auth_rp_id = rp_id;
        self.pin_uv_auth_rp_provided = self.pin_uv_auth_rp_id.is_some();
    }

    fn pin_uv_auth_token(&self) -> Option<[u8; 32]> {
        self.pin_uv_auth_token.as_ref().map(|token| {
            let mut copy = [0u8; 32];
            copy.copy_from_slice(token);
            copy
        })
    }

    fn has_permission(&self, permission: u8) -> bool {
        (self.pin_uv_auth_permissions & permission) != 0
    }

    fn permissions_rp_id(&self) -> Option<&str> {
        self.pin_uv_auth_rp_id.as_deref()
    }

    fn should_bind_pin_token_to_rp(&self) -> bool {
        self.pin_uv_auth_rp_provided
    }

    fn set_permissions_rp_id(&mut self, rp_id: &str) {
        if !self.should_bind_pin_token_to_rp() {
            return;
        }
        if let Some(mut existing) = self.pin_uv_auth_rp_id.take() {
            existing.zeroize();
        }
        self.pin_uv_auth_rp_id = Some(rp_id.to_string());
    }
}

impl Drop for PinState {
    fn drop(&mut self) {
        self.clear_pin_uv_auth_token();
    }
}

struct CredentialManagementState {
    rp_list: Vec<String>,
    rp_index: usize,
    credential_list: Vec<usize>,
    credential_index: usize,
    current_rp: Option<String>,
}

impl CredentialManagementState {
    fn new() -> Self {
        Self {
            rp_list: Vec::new(),
            rp_index: 0,
            credential_list: Vec::new(),
            credential_index: 0,
            current_rp: None,
        }
    }

    fn reset_credentials(&mut self) {
        self.credential_list.clear();
        self.credential_index = 0;
        self.current_rp = None;
    }
}

struct PendingHmacSecret {
    keys: PinUvSessionKeys,
    salt_plaintext: Vec<u8>,
}

impl PendingHmacSecret {
    fn new(keys: PinUvSessionKeys, salt_plaintext: Vec<u8>) -> Self {
        Self {
            keys,
            salt_plaintext,
        }
    }

    fn encrypt_output_for(&self, cred_random: Option<&Vec<u8>>) -> Result<Option<Vec<u8>>, u8> {
        if let Some(random) = cred_random {
            let mut outputs = Vec::new();
            let mut hmac = HmacSha256::new_from_slice(random).map_err(|_| CTAP2_ERR_PROCESSING)?;
            hmac.update(&self.salt_plaintext[..32]);
            outputs.extend_from_slice(&hmac.finalize().into_bytes());
            if self.salt_plaintext.len() == 64 {
                let mut hmac =
                    HmacSha256::new_from_slice(random).map_err(|_| CTAP2_ERR_PROCESSING)?;
                hmac.update(&self.salt_plaintext[32..]);
                outputs.extend_from_slice(&hmac.finalize().into_bytes());
            }
            let encrypted = encrypt_shared_secret(&self.keys.encryption_key, &outputs)?;
            Ok(Some(encrypted))
        } else {
            Ok(None)
        }
    }
}

impl Drop for PendingHmacSecret {
    fn drop(&mut self) {
        self.salt_plaintext.zeroize();
    }
}

struct PendingAssertion {
    rp_id: String,
    client_hash: Vec<u8>,
    user_present: bool,
    user_verified: bool,
    remaining_credentials: VecDeque<Vec<u8>>,
    hmac_secret: Option<PendingHmacSecret>,
}

impl Drop for PendingAssertion {
    fn drop(&mut self) {
        self.client_hash.zeroize();
    }
}

struct HmacSecretRequest {
    key_agreement: Vec<(Value, Value)>,
    salt_enc: Vec<u8>,
    salt_auth: Vec<u8>,
    protocol: PinProtocol,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum PinProtocol {
    Pqc,
    Classic(ClassicPinProtocol),
}

impl PinProtocol {
    fn from_identifier(value: i128) -> Result<Self, u8> {
        if value == i128::from(PIN_UV_AUTH_PROTOCOL_PQC) {
            Ok(PinProtocol::Pqc)
        } else if value == i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V1) {
            Ok(PinProtocol::Classic(ClassicPinProtocol::V1))
        } else if value == i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V2) {
            Ok(PinProtocol::Classic(ClassicPinProtocol::V2))
        } else {
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }
}

enum PinProtocolSession {
    Pqc {
        param_set: KemParamSet,
        secret_key: KemSecretKey,
        public_key: Vec<u8>,
    },
    Classic {
        protocol: ClassicPinProtocol,
        public_key: EncodedPoint,
        secret_key: P256SecretKey,
    },
}

impl PinProtocolSession {
    fn protocol(&self) -> PinProtocol {
        match self {
            PinProtocolSession::Pqc { .. } => PinProtocol::Pqc,
            PinProtocolSession::Classic { protocol, .. } => PinProtocol::Classic(*protocol),
        }
    }

    fn key_agreement_value(&self) -> Value {
        match self {
            PinProtocolSession::Pqc {
                param_set,
                public_key,
                ..
            } => {
                let alg = cose_alg_for_kem_param_set(*param_set);
                cose_akp_key_map(alg, public_key)
            }
            PinProtocolSession::Classic { public_key, .. } => {
                let (x, y) = match (public_key.x(), public_key.y()) {
                    (Some(x_bytes), Some(y_bytes)) => (x_bytes.to_vec(), y_bytes.to_vec()),
                    _ => (Vec::new(), Vec::new()),
                };
                canonical_map(vec![
                    (
                        Value::Integer(Integer::from(1)),
                        Value::Integer(Integer::from(2)),
                    ),
                    (
                        Value::Integer(Integer::from(3)),
                        Value::Integer(Integer::from(-25)),
                    ),
                    (
                        Value::Integer(Integer::from(-1)),
                        Value::Integer(Integer::from(1)),
                    ),
                    (Value::Integer(Integer::from(-2)), Value::Bytes(x)),
                    (Value::Integer(Integer::from(-3)), Value::Bytes(y)),
                ])
            }
        }
    }

    fn derive_session_keys(
        self,
        platform_key: &[(Value, Value)],
    ) -> Result<(PinUvSessionKeys, Vec<u8>), u8> {
        match self {
            PinProtocolSession::Pqc {
                param_set,
                secret_key,
                public_key,
            } => {
                let Some(ciphertext_bytes) = platform_key
                    .iter()
                    .find(|(k, _)| *k == Value::Integer(Integer::from(-2)))
                    .and_then(|(_, v)| match v {
                        Value::Bytes(bytes) => Some(bytes.clone()),
                        _ => None,
                    })
                else {
                    return Err(CTAP1_ERR_INVALID_PARAMETER);
                };
                let ciphertext = Ciphertext(ciphertext_bytes.clone());
                let shared = trussed_mlkem::decapsulate(param_set, &secret_key, &ciphertext)
                    .map_err(|_| CTAP1_ERR_INVALID_PARAMETER)?;
                let mut hasher = Sha256::new();
                hasher.update(&public_key);
                hasher.update(&ciphertext_bytes);
                let transcript_hash = hasher.finalize().to_vec();
                let keys = derive_pqc_pin_uv_session_keys(&shared.0, &transcript_hash);
                Ok((keys, transcript_hash))
            }
            PinProtocolSession::Classic {
                protocol,
                public_key,
                secret_key,
            } => {
                let Some(peer_x) = platform_key
                    .iter()
                    .find(|(k, _)| *k == Value::Integer(Integer::from(-2)))
                    .and_then(|(_, v)| match v {
                        Value::Bytes(bytes) => Some(bytes.clone()),
                        _ => None,
                    })
                else {
                    return Err(CTAP1_ERR_INVALID_PARAMETER);
                };
                let Some(peer_y) = platform_key
                    .iter()
                    .find(|(k, _)| *k == Value::Integer(Integer::from(-3)))
                    .and_then(|(_, v)| match v {
                        Value::Bytes(bytes) => Some(bytes.clone()),
                        _ => None,
                    })
                else {
                    return Err(CTAP1_ERR_INVALID_PARAMETER);
                };
                if peer_x.len() != 32 || peer_y.len() != 32 {
                    return Err(CTAP1_ERR_INVALID_PARAMETER);
                }

                let mut peer_encoded = [0u8; 65];
                peer_encoded[0] = 0x04;
                peer_encoded[1..33].copy_from_slice(&peer_x);
                peer_encoded[33..65].copy_from_slice(&peer_y);

                let peer_public = P256PublicKey::from_sec1_bytes(&peer_encoded)
                    .map_err(|_| CTAP1_ERR_INVALID_PARAMETER)?;
                let shared =
                    diffie_hellman(secret_key.to_nonzero_scalar(), peer_public.as_affine());

                let auth_public_bytes = public_key.as_bytes();
                let mut hasher = Sha256::new();
                hasher.update(auth_public_bytes);
                hasher.update(&peer_encoded);
                let transcript_hash = hasher.finalize().to_vec();

                let shared_bytes = shared.raw_secret_bytes();
                let keys = derive_classic_pin_uv_session_keys(protocol, shared_bytes.as_ref());
                Ok((keys, transcript_hash))
            }
        }
    }
}

#[cfg(test)]
mod tests;

pub struct CtapApp<C> {
    client: C,
    aaguid: [u8; 16],
    pin_state: PinState,
    pin_protocol_session: Option<PinProtocolSession>,
    platform_declined_pqc: bool,
    suppress_attestation: bool,
    cred_mgmt_state: CredentialManagementState,
    pending_assertion: Option<PendingAssertion>,
    attestation_private_key: Option<Vec<u8>>,
    attestation_certificate_chain: Option<Vec<Vec<u8>>>,
    #[cfg(test)]
    stored_credentials: Vec<StoredCredential>,
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    pub fn new(client: C, aaguid: [u8; 16]) -> Self {
        let mut app = Self {
            client,
            aaguid,
            pin_state: PinState::new(),
            pin_protocol_session: None,
            platform_declined_pqc: false,
            suppress_attestation: false,
            cred_mgmt_state: CredentialManagementState::new(),
            pending_assertion: None,
            attestation_private_key: None,
            attestation_certificate_chain: None,
            #[cfg(test)]
            stored_credentials: Vec::new(),
        };

        if app.load_attestation_material().is_err() {
            app.clear_attestation_material();
        }

        app
    }

    pub fn suppress_attestation(&mut self, suppress: bool) {
        self.suppress_attestation = suppress;
    }
    fn verify_pin_auth(
        protocol: PinProtocol,
        keys: &PinUvSessionKeys,
        data: &[u8],
        provided: &[u8],
    ) -> Result<(), u8> {
        let mut mac =
            HmacSha256::new_from_slice(&keys.auth_key).map_err(|_| CTAP2_ERR_PROCESSING)?;
        mac.update(data);
        let result = mac.finalize().into_bytes();
        match protocol {
            PinProtocol::Classic(ClassicPinProtocol::V1)
            | PinProtocol::Classic(ClassicPinProtocol::V2) => {
                if provided.len() != 16 {
                    return Err(CTAP2_ERR_PIN_AUTH_INVALID);
                }
                if result[..16] == provided[..16] {
                    Ok(())
                } else {
                    Err(CTAP2_ERR_PIN_AUTH_INVALID)
                }
            }
            PinProtocol::Pqc => {
                if provided.len() != 32 {
                    return Err(CTAP2_ERR_PIN_AUTH_INVALID);
                }
                if result[..] == provided[..] {
                    Ok(())
                } else {
                    Err(CTAP2_ERR_PIN_AUTH_INVALID)
                }
            }
        }
    }

    fn decrypt_pin_block_checked(
        protocol: PinProtocol,
        keys: &PinUvSessionKeys,
        transcript_hash: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, u8> {
        match protocol {
            PinProtocol::Pqc => {
                if ciphertext.len() < 16 {
                    return Err(CTAP1_ERR_INVALID_PARAMETER);
                }
                let nonce = [0u8; 12];
                decrypt_pqc_pin_block(keys, &nonce, ciphertext, transcript_hash)
                    .map_err(|_| CTAP2_ERR_PIN_AUTH_INVALID)
            }
            PinProtocol::Classic(classic) => decrypt_classic_pin_block(classic, keys, ciphertext)
                .map_err(|_| CTAP2_ERR_PIN_AUTH_INVALID),
        }
    }

    fn extract_new_pin(plaintext: &mut [u8]) -> Result<Vec<u8>, u8> {
        if plaintext.len() != 64 {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        let mut end = plaintext.len();
        while end > 0 && plaintext[end - 1] == 0 {
            end -= 1;
        }
        let pin = plaintext[..end].to_vec();
        plaintext.zeroize();
        if pin.len() < PinState::MIN_PIN_LENGTH {
            return Err(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        if pin.len() > 63 {
            return Err(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        Ok(pin)
    }

    fn hash_pin(pin: &[u8]) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(pin);
        let digest = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }

    fn ensure_supported_pin_uv_protocol(protocol: i128) -> Result<(), u8> {
        if protocol < i32::MIN as i128 || protocol > i32::MAX as i128 {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let protocol_i32 = protocol as i32;
        if SUPPORTED_PIN_UV_PROTOCOLS.contains(&protocol_i32) {
            Ok(())
        } else {
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    fn as_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], u8> {
        if bytes.len() != N {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    fn credential_allows(
        credential: &StoredCredential,
        user_verified: bool,
        allow_list_provided: bool,
    ) -> bool {
        match credential.cred_protect.unwrap_or(1) {
            3 => user_verified,
            2 => user_verified || allow_list_provided,
            _ => true,
        }
    }

    fn requested_pin_protocol(&mut self, map: &[(Value, Value)]) -> Result<PinProtocol, u8> {
        if let Some(Value::Integer(int)) = Self::map_get(map, Value::Integer(Integer::from(1))) {
            let value: i128 = int.clone().into();
            match value {
                v if v == i128::from(PIN_UV_AUTH_PROTOCOL_PQC) => {
                    self.platform_declined_pqc = false;
                    Ok(PinProtocol::Pqc)
                }
                v if v == i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V2) => {
                    self.platform_declined_pqc = true;
                    Ok(PinProtocol::Classic(ClassicPinProtocol::V2))
                }
                v if v == i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V1) => {
                    self.platform_declined_pqc = true;
                    Ok(PinProtocol::Classic(ClassicPinProtocol::V1))
                }
                _ => Err(CTAP1_ERR_INVALID_PARAMETER),
            }
        } else if self.platform_declined_pqc {
            Ok(PinProtocol::Classic(ClassicPinProtocol::V2))
        } else {
            Ok(PinProtocol::Pqc)
        }
    }

    fn take_session(&mut self, protocol: PinProtocol) -> Result<PinProtocolSession, u8> {
        match self.pin_protocol_session.take() {
            Some(session) if session.protocol() == protocol => Ok(session),
            Some(session) => {
                self.pin_protocol_session = Some(session);
                Err(CTAP2_ERR_PIN_AUTH_INVALID)
            }
            None => Err(CTAP2_ERR_PIN_AUTH_INVALID),
        }
    }

    fn client_pin_get_key_agreement(&mut self, protocol: PinProtocol) -> Result<Vec<u8>, u8> {
        let session = match protocol {
            PinProtocol::Pqc => {
                let param_set = KemParamSet::MLKem512;
                let (public_key, secret_key) = trussed_mlkem::keypair(param_set);
                PinProtocolSession::Pqc {
                    param_set,
                    secret_key,
                    public_key: public_key.0.clone(),
                }
            }
            PinProtocol::Classic(classic_protocol) => {
                let secret_key = loop {
                    let bytes = syscall!(self.client.random_bytes(32)).bytes;
                    if bytes.len() != 32 {
                        continue;
                    }
                    match P256SecretKey::from_slice(bytes.as_slice()) {
                        Ok(secret) => break secret,
                        Err(_) => continue,
                    }
                };
                let public_key = secret_key.public_key().to_encoded_point(false);
                PinProtocolSession::Classic {
                    protocol: classic_protocol,
                    public_key,
                    secret_key,
                }
            }
        };
        let mut key_map = session.key_agreement_value();
        if let Value::Map(mut entries) = key_map {
            canonical_sort(&mut entries);
            key_map = Value::Map(entries);
        }
        self.pin_protocol_session = Some(session);
        let response = canonical_map(vec![(Value::Integer(Integer::from(1)), key_map)]);
        let mut encoded = Vec::new();
        into_writer(&response, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    fn client_pin_set_pin(
        &mut self,
        protocol: PinProtocol,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, u8> {
        if self.pin_state.is_set() {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let key_agreement = match Self::map_get(map, Value::Integer(Integer::from(3))) {
            Some(Value::Map(entries)) => entries,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let new_pin_enc = match Self::map_get(map, Value::Integer(Integer::from(5))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let pin_auth_param = match Self::map_get(map, Value::Integer(Integer::from(4))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let session = self.take_session(protocol)?;
        let (keys, transcript_hash) = session.derive_session_keys(key_agreement)?;
        Self::verify_pin_auth(protocol, &keys, &new_pin_enc, &pin_auth_param)?;
        let mut plaintext =
            Self::decrypt_pin_block_checked(protocol, &keys, &transcript_hash, &new_pin_enc)?;
        let mut new_pin = Self::extract_new_pin(&mut plaintext)?;
        let hash = Self::hash_pin(&new_pin);
        new_pin.zeroize();
        self.pin_state.set_pin(hash);
        Ok(vec![CTAP2_OK])
    }

    fn client_pin_change_pin(
        &mut self,
        protocol: PinProtocol,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, u8> {
        if !self.pin_state.is_set() {
            return Err(CTAP2_ERR_PIN_NOT_SET);
        }
        let key_agreement = match Self::map_get(map, Value::Integer(Integer::from(3))) {
            Some(Value::Map(entries)) => entries,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let new_pin_enc = match Self::map_get(map, Value::Integer(Integer::from(5))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let pin_hash_enc = match Self::map_get(map, Value::Integer(Integer::from(6))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let pin_auth_param = match Self::map_get(map, Value::Integer(Integer::from(4))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let session = self.take_session(protocol)?;
        let (keys, transcript_hash) = session.derive_session_keys(key_agreement)?;
        let mut auth_data = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
        auth_data.extend_from_slice(&new_pin_enc);
        auth_data.extend_from_slice(&pin_hash_enc);
        Self::verify_pin_auth(protocol, &keys, &auth_data, &pin_auth_param)?;

        let mut current_plain =
            Self::decrypt_pin_block_checked(protocol, &keys, &transcript_hash, &pin_hash_enc)?;
        let current_hash = Self::as_array::<16>(&current_plain)?;
        current_plain.zeroize();
        if let Err(err) = self.pin_state.verify_pin_hash(&current_hash) {
            return Err(err);
        }

        let mut new_pin_plain =
            Self::decrypt_pin_block_checked(protocol, &keys, &transcript_hash, &new_pin_enc)?;
        let mut new_pin = Self::extract_new_pin(&mut new_pin_plain)?;
        let hash = Self::hash_pin(&new_pin);
        new_pin.zeroize();
        self.pin_state.set_pin(hash);
        Ok(vec![CTAP2_OK])
    }

    fn client_pin_get_token_common(
        &mut self,
        protocol: PinProtocol,
        map: &[(Value, Value)],
        permissions: u8,
        rp_id: Option<String>,
    ) -> Result<Vec<u8>, u8> {
        if !self.pin_state.is_set() {
            return Err(CTAP2_ERR_PIN_NOT_SET);
        }
        let key_agreement = match Self::map_get(map, Value::Integer(Integer::from(3))) {
            Some(Value::Map(entries)) => entries,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let pin_hash_enc = match Self::map_get(map, Value::Integer(Integer::from(6))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let pin_auth_param = match Self::map_get(map, Value::Integer(Integer::from(4))) {
            Some(Value::Bytes(bytes)) => Some(bytes.clone()),
            Some(_) => return Err(CTAP2_ERR_INVALID_CBOR),
            None => None,
        };

        let session = self.take_session(protocol)?;
        let (keys, transcript_hash) = session.derive_session_keys(key_agreement)?;
        if let Some(pin_auth_param) = pin_auth_param.as_ref() {
            Self::verify_pin_auth(protocol, &keys, &pin_hash_enc, pin_auth_param)?;
        }

        let mut plain =
            Self::decrypt_pin_block_checked(protocol, &keys, &transcript_hash, &pin_hash_enc)?;
        let current_hash = Self::as_array::<16>(&plain)?;
        plain.zeroize();
        if let Err(err) = self.pin_state.verify_pin_hash(&current_hash) {
            return Err(err);
        }

        let random = syscall!(self.client.random_bytes(32)).bytes;
        if random.len() != 32 {
            return Err(CTAP2_ERR_PROCESSING);
        }
        let mut token = [0u8; 32];
        token.copy_from_slice(random.as_slice());
        let encrypted = match protocol {
            PinProtocol::Pqc => {
                let nonce = [0u8; 12];
                encrypt_pqc_pin_block(&keys, &nonce, &token, &transcript_hash)
            }
            PinProtocol::Classic(classic_protocol) => match classic_protocol {
                ClassicPinProtocol::V1 => {
                    encrypt_classic_pin_block(ClassicPinProtocol::V1, &keys, None, &token)
                        .map_err(|_| CTAP2_ERR_PROCESSING)?
                }
                ClassicPinProtocol::V2 => {
                    let iv_bytes = syscall!(self.client.random_bytes(16)).bytes;
                    if iv_bytes.len() != 16 {
                        return Err(CTAP2_ERR_PROCESSING);
                    }
                    let mut iv = [0u8; 16];
                    iv.copy_from_slice(iv_bytes.as_slice());
                    encrypt_classic_pin_block(ClassicPinProtocol::V2, &keys, Some(&iv), &token)
                        .map_err(|_| CTAP2_ERR_PROCESSING)?
                }
            },
        };
        self.pin_state
            .set_pin_uv_auth_token(token, permissions, rp_id);
        let response = canonical_map(vec![
            (Value::Integer(Integer::from(2)), Value::Bytes(encrypted)),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(u64::from(self.pin_state.retries()))),
            ),
        ]);
        let mut encoded = Vec::new();
        into_writer(&response, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    fn client_pin_get_token_legacy(
        &mut self,
        protocol: PinProtocol,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, u8> {
        if Self::map_get(map, Value::Integer(Integer::from(9))).is_some()
            || Self::map_get(map, Value::Integer(Integer::from(10))).is_some()
        {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        let permissions = PIN_PERMISSION_MC | PIN_PERMISSION_GA;
        self.client_pin_get_token_common(protocol, map, permissions, None)
    }

    fn client_pin_get_token_with_permissions(
        &mut self,
        protocol: PinProtocol,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, u8> {
        let permissions_value = match Self::map_get(map, Value::Integer(Integer::from(9))) {
            Some(Value::Integer(value)) => {
                let int_value: i128 = value.clone().into();
                if int_value <= 0 || int_value > u8::MAX as i128 {
                    return Err(CTAP1_ERR_INVALID_PARAMETER);
                }
                int_value as u8
            }
            Some(_) => return Err(CTAP1_ERR_INVALID_PARAMETER),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        if permissions_value == 0 {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        let rp_id_value = match Self::map_get(map, Value::Integer(Integer::from(10))) {
            Some(Value::Text(text)) => Some(text.clone()),
            Some(_) => return Err(CTAP2_ERR_INVALID_CBOR),
            None => None,
        };

        if permissions_value & (PIN_PERMISSION_MC | PIN_PERMISSION_GA) != 0 && rp_id_value.is_none()
        {
            return Err(CTAP2_ERR_MISSING_PARAMETER);
        }
        if permissions_value & PIN_PERMISSION_CM != 0 && rp_id_value.is_some() {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        let supported_permissions = PIN_PERMISSION_MC | PIN_PERMISSION_GA | PIN_PERMISSION_CM;
        if permissions_value & !supported_permissions != 0 {
            return Err(CTAP2_ERR_UNAUTHORIZED_PERMISSION);
        }

        let assigned_permissions = permissions_value & supported_permissions;
        self.client_pin_get_token_common(protocol, map, assigned_permissions, rp_id_value)
    }

    fn ensure_pin_token_permission_for_rp(
        &mut self,
        permission: u8,
        rp_id: &str,
    ) -> Result<(), u8> {
        if !self.pin_state.has_permission(permission) {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if !self.pin_state.should_bind_pin_token_to_rp() {
            return Ok(());
        }
        match self.pin_state.permissions_rp_id() {
            Some(existing) => {
                if existing != rp_id {
                    return Err(CTAP2_ERR_PIN_AUTH_INVALID);
                }
            }
            None => self.pin_state.set_permissions_rp_id(rp_id),
        }
        Ok(())
    }

    fn ensure_pin_token_permission_for_cm(
        &mut self,
        subcommand: u8,
        params: Option<&[(Value, Value)]>,
    ) -> Result<(), u8> {
        if !self.pin_state.has_permission(PIN_PERMISSION_CM) {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let Some(binding) = self
            .pin_state
            .permissions_rp_id()
            .map(|value| value.to_string())
        else {
            return Ok(());
        };
        match subcommand {
            0x01 | 0x02 | 0x03 => Err(CTAP2_ERR_PIN_AUTH_INVALID),
            0x04 => {
                let params = params.ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
                let rp_hash = match Self::map_get(params, Value::Integer(Integer::from(1))) {
                    Some(Value::Bytes(bytes)) => bytes,
                    _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
                };
                if Self::cm_hash_rp_id(&binding) == *rp_hash {
                    Ok(())
                } else {
                    Err(CTAP2_ERR_PIN_AUTH_INVALID)
                }
            }
            0x05 => match self.cred_mgmt_state.current_rp.as_deref() {
                Some(current) if current == binding => Ok(()),
                _ => Err(CTAP2_ERR_PIN_AUTH_INVALID),
            },
            0x06 | 0x07 => {
                let params = params.ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
                let descriptor = match Self::map_get(params, Value::Integer(Integer::from(2))) {
                    Some(Value::Map(map)) => map,
                    _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
                };
                let Some(Value::Bytes(id)) = Self::map_get(descriptor, Value::Text("id".into()))
                else {
                    return Err(CTAP2_ERR_MISSING_PARAMETER);
                };
                let credentials = self.load_credentials()?;
                let Some(credential) = credentials.iter().find(|cred| cred.credential_id == *id)
                else {
                    return Err(CTAP2_ERR_NO_CREDENTIALS);
                };
                if credential.rp_id == binding {
                    Ok(())
                } else {
                    Err(CTAP2_ERR_PIN_AUTH_INVALID)
                }
            }
            _ => Ok(()),
        }
    }

    fn handle_client_pin(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let request: Value = from_reader(payload).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        let map = match request {
            Value::Map(map) => map,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };
        let subcommand = match Self::map_get(&map, Value::Integer(Integer::from(2))) {
            Some(Value::Integer(int)) => {
                let value: i128 = int.clone().into();
                value as u8
            }
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let protocol = self.requested_pin_protocol(&map)?;
        match subcommand {
            0x01 => self.client_pin_get_retries(),
            0x02 => self.client_pin_get_key_agreement(protocol),
            0x03 => self.client_pin_set_pin(protocol, &map),
            0x04 => self.client_pin_change_pin(protocol, &map),
            0x05 => self.client_pin_get_token_legacy(protocol, &map),
            0x09 => self.client_pin_get_token_with_permissions(protocol, &map),
            _ => Err(CTAP1_ERR_INVALID_PARAMETER),
        }
    }

    fn client_pin_get_retries(&mut self) -> Result<Vec<u8>, u8> {
        let mut entries = vec![(
            Value::Integer(Integer::from(0x03)),
            Value::Integer(Integer::from(u64::from(self.pin_state.retries()))),
        )];

        if self.pin_state.needs_power_cycle() {
            entries.push((Value::Integer(Integer::from(0x04)), Value::Bool(true)));
        }

        let response = canonical_map(entries);
        let mut encoded = Vec::new();
        into_writer(&response, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    fn clear_attestation_material(&mut self) {
        if let Some(mut key) = self.attestation_private_key.take() {
            key.zeroize();
        }
        self.attestation_certificate_chain = None;
    }

    #[cfg(not(test))]
    fn store_path() -> Result<PathBuf, u8> {
        PathBuf::try_from(CREDENTIAL_STORE_PATH).map_err(|_| CTAP2_ERR_PROCESSING)
    }

    #[cfg(not(test))]
    fn attestation_store_path() -> Result<PathBuf, u8> {
        PathBuf::try_from(ATTESTATION_STORE_PATH).map_err(|_| CTAP2_ERR_PROCESSING)
    }

    #[cfg(not(test))]
    fn load_attestation_material(&mut self) -> Result<(), u8> {
        let path = Self::attestation_store_path()?;
        match try_syscall!(self.client.read_file(Location::Internal, path.clone())) {
            Ok(reply) => {
                let data = reply.data.as_slice();
                if data.is_empty() {
                    self.clear_attestation_material();
                    return Ok(());
                }

                let stored: StoredAttestation =
                    from_reader(data).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
                if stored.private_key.is_empty()
                    || stored.certificate_chain.is_empty()
                    || stored.private_key.len() != 32
                {
                    self.clear_attestation_material();
                    return Err(CTAP2_ERR_INVALID_CBOR);
                }

                self.clear_attestation_material();
                self.attestation_private_key = Some(stored.private_key);
                self.attestation_certificate_chain = Some(stored.certificate_chain);
                Ok(())
            }
            Err(_) => {
                self.clear_attestation_material();
                Ok(())
            }
        }
    }

    #[cfg(test)]
    fn load_attestation_material(&mut self) -> Result<(), u8> {
        Ok(())
    }

    fn attestation_signature(
        &self,
        auth_data: &[u8],
        client_hash: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<Vec<u8>>)>, u8> {
        let (key_bytes, chain) = match (
            self.attestation_private_key.as_ref(),
            self.attestation_certificate_chain.as_ref(),
        ) {
            (Some(key), Some(chain)) if !chain.is_empty() => (key, chain),
            _ => return Ok(None),
        };

        if key_bytes.len() != 32 {
            return Err(CTAP2_ERR_PROCESSING);
        }

        let secret_key = P256SecretKey::from_slice(key_bytes).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let signing_key = SigningKey::from(secret_key);
        let mut message = Vec::with_capacity(auth_data.len() + client_hash.len());
        message.extend_from_slice(auth_data);
        message.extend_from_slice(client_hash);
        let signature: P256EcdsaSignature = signing_key.sign(&message);
        let der = signature.to_der();
        Ok(Some((der.as_bytes().to_vec(), chain.clone())))
    }

    #[cfg(not(test))]
    fn load_credentials(&mut self) -> Result<Vec<StoredCredential>, u8> {
        let path = Self::store_path()?;
        match try_syscall!(self.client.read_file(Location::Internal, path.clone())) {
            Ok(reply) => {
                let data = reply.data.as_slice();
                if data.is_empty() {
                    Ok(Vec::new())
                } else {
                    from_reader(data).map_err(|_| CTAP2_ERR_INVALID_CBOR)
                }
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    #[cfg(test)]
    fn load_credentials(&mut self) -> Result<Vec<StoredCredential>, u8> {
        Ok(self.stored_credentials.clone())
    }

    #[cfg(not(test))]
    fn save_credentials(&mut self, creds: &[StoredCredential]) -> Result<(), u8> {
        let mut encoded = Vec::new();
        into_writer(creds, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let message = Message::from_slice(&encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let path = Self::store_path()?;
        try_syscall!(self
            .client
            .write_file(Location::Internal, path, message, None))
        .map_err(|_| CTAP2_ERR_PROCESSING)?;
        Ok(())
    }

    #[cfg(test)]
    fn save_credentials(&mut self, creds: &[StoredCredential]) -> Result<(), u8> {
        self.stored_credentials = creds.to_vec();
        Ok(())
    }

    fn map_get<'a>(map: &'a [(Value, Value)], key: Value) -> Option<&'a Value> {
        map.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    fn cm_hash_rp_id(rp_id: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        hasher.finalize().to_vec()
    }

    fn process_hmac_secret_for_assertion(
        &mut self,
        request: &HmacSecretRequest,
        cred_random_with_uv: Option<&Vec<u8>>,
        cred_random_without_uv: Option<&Vec<u8>>,
        user_verified: bool,
    ) -> Result<(Option<Vec<u8>>, PendingHmacSecret), u8> {
        let session = self.take_session(request.protocol)?;
        let (keys, _) = session.derive_session_keys(&request.key_agreement)?;

        let mut mac =
            HmacSha256::new_from_slice(&keys.auth_key).map_err(|_| CTAP2_ERR_PROCESSING)?;
        mac.update(&request.salt_enc);
        let computed = mac.finalize().into_bytes();
        if computed[..16] != request.salt_auth[..] {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }

        let plaintext = decrypt_shared_secret(&keys.encryption_key, &request.salt_enc)?;
        if plaintext.len() != 32 && plaintext.len() != 64 {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        let cred_random = if user_verified {
            cred_random_with_uv
        } else {
            cred_random_without_uv
        };

        let pending = PendingHmacSecret::new(keys, plaintext);
        let encrypted = pending.encrypt_output_for(cred_random)?;
        Ok((encrypted, pending))
    }

    fn cm_get_metadata(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        let credentials = self.load_credentials()?;
        let existing = credentials.len() as u64;
        let remaining = 2048u64.saturating_sub(existing);
        Ok(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(existing)),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Integer(Integer::from(remaining)),
            ),
        ])
    }

    fn cm_enumerate_rps_begin(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        let credentials = self.load_credentials()?;
        let mut rp_ids: Vec<String> = credentials.iter().map(|cred| cred.rp_id.clone()).collect();
        rp_ids.sort();
        rp_ids.dedup();
        if rp_ids.is_empty() {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }

        let total = rp_ids.len() as u64;
        let first = rp_ids[0].clone();
        self.cred_mgmt_state.rp_list = rp_ids;
        self.cred_mgmt_state.rp_index = 1;
        self.cred_mgmt_state.reset_credentials();

        let rp_entry = canonical_map(vec![(Value::Text("id".into()), Value::Text(first.clone()))]);
        let hash = Self::cm_hash_rp_id(&first);
        Ok(vec![
            (Value::Integer(Integer::from(3)), rp_entry),
            (Value::Integer(Integer::from(4)), Value::Bytes(hash)),
            (
                Value::Integer(Integer::from(5)),
                Value::Integer(Integer::from(total)),
            ),
        ])
    }

    fn cm_enumerate_rps_next(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        if self.cred_mgmt_state.rp_index >= self.cred_mgmt_state.rp_list.len() {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }
        let rp_id = self.cred_mgmt_state.rp_list[self.cred_mgmt_state.rp_index].clone();
        self.cred_mgmt_state.rp_index += 1;
        let rp_entry = canonical_map(vec![(Value::Text("id".into()), Value::Text(rp_id.clone()))]);
        let hash = Self::cm_hash_rp_id(&rp_id);
        Ok(vec![
            (Value::Integer(Integer::from(3)), rp_entry),
            (Value::Integer(Integer::from(4)), Value::Bytes(hash)),
        ])
    }

    fn cm_find_rp_indices(&self, credentials: &[StoredCredential], rp_hash: &[u8]) -> Vec<usize> {
        credentials
            .iter()
            .enumerate()
            .filter_map(|(idx, cred)| {
                let hash = Self::cm_hash_rp_id(&cred.rp_id);
                if hash == rp_hash {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect()
    }

    fn cm_credential_response(
        credential: &StoredCredential,
        total: usize,
    ) -> Result<Vec<(Value, Value)>, u8> {
        let mut user_entries = vec![(
            Value::Text("id".into()),
            Value::Bytes(credential.user_id.clone()),
        )];
        if let Some(name) = &credential.user_name {
            user_entries.push((Value::Text("name".into()), Value::Text(name.clone())));
        }
        if let Some(display) = &credential.user_display_name {
            user_entries.push((
                Value::Text("displayName".into()),
                Value::Text(display.clone()),
            ));
        }
        let user_map = canonical_map(user_entries);

        let credential_descriptor = canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("id".into()),
                Value::Bytes(credential.credential_id.clone()),
            ),
        ]);

        let public_key_value: Value = from_reader::<Value, _>(&credential.public_key[..])
            .map_err(|_| CTAP2_ERR_PROCESSING)?;

        Ok(vec![
            (Value::Integer(Integer::from(6)), user_map),
            (Value::Integer(Integer::from(7)), credential_descriptor),
            (Value::Integer(Integer::from(8)), public_key_value),
            (
                Value::Integer(Integer::from(9)),
                Value::Integer(Integer::from(total as u64)),
            ),
            (
                Value::Integer(Integer::from(10)),
                Value::Integer(Integer::from(credential.cred_protect.unwrap_or(1) as u64)),
            ),
        ])
    }

    fn cm_enumerate_credentials_begin(
        &mut self,
        params: &[(Value, Value)],
    ) -> Result<Vec<(Value, Value)>, u8> {
        let rp_hash = match Self::map_get(params, Value::Integer(Integer::from(1))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let credentials = self.load_credentials()?;
        let indices = self.cm_find_rp_indices(&credentials, &rp_hash);
        if indices.is_empty() {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }

        let first_idx = indices[0];
        let response = Self::cm_credential_response(&credentials[first_idx], indices.len())?;

        self.cred_mgmt_state.current_rp = Some(credentials[first_idx].rp_id.clone());
        self.cred_mgmt_state.credential_list = indices;
        self.cred_mgmt_state.credential_index = 1;

        Ok(response)
    }

    fn cm_enumerate_credentials_next(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        if self.cred_mgmt_state.credential_index >= self.cred_mgmt_state.credential_list.len() {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }
        let credentials = self.load_credentials()?;
        let idx = self.cred_mgmt_state.credential_list[self.cred_mgmt_state.credential_index];
        self.cred_mgmt_state.credential_index += 1;
        Self::cm_credential_response(
            &credentials[idx],
            self.cred_mgmt_state.credential_list.len(),
        )
    }

    fn cm_delete_credential(&mut self, params: &[(Value, Value)]) -> Result<(), u8> {
        let descriptor = match Self::map_get(params, Value::Integer(Integer::from(2))) {
            Some(Value::Map(map)) => map,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let Some(Value::Bytes(id)) = Self::map_get(descriptor, Value::Text("id".into())) else {
            return Err(CTAP2_ERR_MISSING_PARAMETER);
        };
        let mut credentials = self.load_credentials()?;
        let Some(pos) = credentials
            .iter()
            .position(|cred| cred.credential_id == *id)
        else {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        };
        credentials.remove(pos);
        self.save_credentials(&credentials)?;
        self.cred_mgmt_state.rp_list.clear();
        self.cred_mgmt_state.rp_index = 0;
        self.cred_mgmt_state.reset_credentials();
        Ok(())
    }

    fn cm_update_user_information(&mut self, params: &[(Value, Value)]) -> Result<(), u8> {
        let descriptor = match Self::map_get(params, Value::Integer(Integer::from(2))) {
            Some(Value::Map(map)) => map,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let Some(Value::Bytes(id)) = Self::map_get(descriptor, Value::Text("id".into())) else {
            return Err(CTAP2_ERR_MISSING_PARAMETER);
        };

        let user_map = match Self::map_get(params, Value::Integer(Integer::from(3))) {
            Some(Value::Map(map)) => map,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let Some(Value::Bytes(user_id)) = Self::map_get(user_map, Value::Text("id".into())) else {
            return Err(CTAP2_ERR_MISSING_PARAMETER);
        };

        let mut credentials = self.load_credentials()?;
        let Some(credential) = credentials
            .iter_mut()
            .find(|cred| cred.credential_id == *id)
        else {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        };
        if credential.user_id != *user_id {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        credential.user_name = Self::map_get(user_map, Value::Text("name".into())).and_then(|v| {
            if let Value::Text(text) = v {
                if text.is_empty() {
                    None
                } else {
                    Some(text.clone())
                }
            } else {
                None
            }
        });
        credential.user_display_name = Self::map_get(user_map, Value::Text("displayName".into()))
            .and_then(|v| {
                if let Value::Text(text) = v {
                    if text.is_empty() {
                        None
                    } else {
                        Some(text.clone())
                    }
                } else {
                    None
                }
            });

        self.save_credentials(&credentials)
    }

    fn attested_auth_data(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        cose_key: &[u8],
        uv: bool,
        sign_count: u32,
        extensions: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let rp_hash = hasher.finalize();

        let mut auth_data =
            Vec::with_capacity(32 + 1 + 4 + 16 + 2 + credential_id.len() + cose_key.len());
        auth_data.extend_from_slice(&rp_hash);
        let mut flags = 0x40 | 0x01; // AT + UP
        if uv {
            flags |= 0x04;
        }
        if extensions.is_some() {
            flags |= 0x80;
        }
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data.extend_from_slice(&self.aaguid);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(cose_key);
        if let Some(ext) = extensions {
            auth_data.extend_from_slice(ext);
        }
        auth_data
    }

    fn assertion_auth_data(
        &self,
        rp_id: &str,
        sign_count: u32,
        user_present: bool,
        user_verified: bool,
        extensions: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let rp_hash = hasher.finalize();

        let mut auth_data = Vec::with_capacity(32 + 1 + 4);
        auth_data.extend_from_slice(&rp_hash);
        let mut flags = 0u8;
        if user_present {
            flags |= 0x01;
        }
        if user_verified {
            flags |= 0x04;
        }
        if extensions.is_some() {
            flags |= 0x80;
        }
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        if let Some(ext) = extensions {
            auth_data.extend_from_slice(ext);
        }
        auth_data
    }

    fn handle_get_info(&mut self) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let mut map = Vec::new();

        map.push((
            Value::Integer(Integer::from(1)),
            Value::Array(vec![
                Value::Text("FIDO_2_1".into()),
                Value::Text("FIDO_2_0".into()),
                Value::Text("U2F_V2".into()),
            ]),
        ));
        map.push((
            Value::Integer(Integer::from(3)),
            Value::Bytes(self.aaguid.to_vec()),
        ));

        map.push((
            Value::Integer(Integer::from(2)),
            Value::Array(vec![
                Value::Text("credProtect".into()),
                Value::Text("hmac-secret".into()),
            ]),
        ));

        let options = canonical_map(vec![
            (Value::Text("rk".into()), Value::Bool(true)),
            (Value::Text("up".into()), Value::Bool(true)),
            (Value::Text("credMgmt".into()), Value::Bool(true)),
            (Value::Text("pinUvAuthToken".into()), Value::Bool(true)),
            (
                Value::Text("clientPin".into()),
                Value::Bool(self.pin_state.is_set()),
            ),
        ]);
        map.push((Value::Integer(Integer::from(4)), options));

        map.push((
            Value::Integer(Integer::from(5)),
            Value::Integer(Integer::from(2048)),
        ));

        map.push((
            Value::Integer(Integer::from(6)),
            Value::Array(vec![
                Value::Integer(Integer::from(i32::from(PIN_UV_AUTH_PROTOCOL_PQC))),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
            ]),
        ));

        map.push((
            Value::Integer(Integer::from(8)),
            Value::Integer(Integer::from(128)),
        ));

        map.push((
            Value::Integer(Integer::from(13)),
            Value::Integer(Integer::from(PinState::MIN_PIN_LENGTH as u64)),
        ));

        let algorithms = [
            CoseAlg::ES256,
            CoseAlg::MLDSA44,
            CoseAlg::MLDSA65,
            CoseAlg::MLDSA87,
        ]
        .into_iter()
        .map(|alg| {
            canonical_map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (
                    Value::Text("alg".into()),
                    Value::Integer(Integer::from(alg as i32)),
                ),
            ])
        })
        .collect();
        map.push((Value::Integer(Integer::from(10)), Value::Array(algorithms)));

        let transports = Value::Array(vec![Value::Text("usb".into())]);
        map.push((Value::Integer(Integer::from(9)), transports));

        canonical_sort(&mut map);
        let mut encoded = Vec::new();
        into_writer(&Value::Map(map), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    fn handle_credential_management(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let request: Value = from_reader(payload).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        let map = match request {
            Value::Map(map) => map,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let subcommand = match Self::map_get(&map, Value::Integer(Integer::from(1))) {
            Some(Value::Integer(int)) => {
                let value: i128 = int.clone().into();
                if value < 0 || value > u8::MAX as i128 {
                    return Err(CTAP1_ERR_INVALID_PARAMETER);
                }
                value as u8
            }
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let subcommand_params = match Self::map_get(&map, Value::Integer(Integer::from(2))) {
            Some(Value::Map(entries)) => Some(entries.clone()),
            Some(_) => return Err(CTAP2_ERR_INVALID_CBOR),
            None => None,
        };

        let protocol_value = match Self::map_get(&map, Value::Integer(Integer::from(3))) {
            Some(Value::Integer(int)) => int.clone().into(),
            _ => return Err(CTAP2_ERR_PIN_AUTH_INVALID),
        };
        Self::ensure_supported_pin_uv_protocol(protocol_value)?;

        let pin_auth_param = match Self::map_get(&map, Value::Integer(Integer::from(4))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            Some(_) => return Err(CTAP2_ERR_PUAT_REQUIRED),
            None => return Err(CTAP2_ERR_PUAT_REQUIRED),
        };
        if pin_auth_param.len() != 16 {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }

        let mut token = self
            .pin_state
            .pin_uv_auth_token()
            .ok_or(CTAP2_ERR_PUAT_REQUIRED)?;
        let mut message = vec![subcommand];
        if let Some(params) = subcommand_params.as_ref() {
            let map_value = canonical_map(params.clone());
            let mut encoded = Vec::new();
            into_writer(&map_value, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
            message.extend_from_slice(&encoded);
        }
        let mut mac = HmacSha256::new_from_slice(&token).map_err(|_| CTAP2_ERR_PROCESSING)?;
        mac.update(&message);
        let computed = mac.finalize().into_bytes();
        token.zeroize();
        if computed[..16] != pin_auth_param[..] {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }

        self.ensure_pin_token_permission_for_cm(
            subcommand,
            subcommand_params.as_ref().map(|params| params.as_slice()),
        )?;

        let response_entries = match subcommand {
            0x01 => Some(self.cm_get_metadata()?),
            0x02 => Some(self.cm_enumerate_rps_begin()?),
            0x03 => Some(self.cm_enumerate_rps_next()?),
            0x04 => {
                let params = subcommand_params
                    .as_ref()
                    .ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
                Some(self.cm_enumerate_credentials_begin(params)?)
            }
            0x05 => Some(self.cm_enumerate_credentials_next()?),
            0x06 => {
                let params = subcommand_params
                    .as_ref()
                    .ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
                self.cm_delete_credential(params)?;
                None
            }
            0x07 => {
                let params = subcommand_params
                    .as_ref()
                    .ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
                self.cm_update_user_information(params)?;
                None
            }
            _ => return Err(CTAP1_ERR_INVALID_PARAMETER),
        };

        if let Some(mut entries) = response_entries {
            canonical_sort(&mut entries);
            let value = Value::Map(entries);
            let mut encoded = Vec::new();
            into_writer(&value, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
            let mut out = Vec::with_capacity(1 + encoded.len());
            out.push(CTAP2_OK);
            out.extend_from_slice(&encoded);
            Ok(out)
        } else {
            Ok(vec![CTAP2_OK])
        }
    }

    fn handle_make_credential(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let request: Value = from_reader(payload).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        let map = match request {
            Value::Map(map) => map,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let client_hash = match Self::map_get(&map, Value::Integer(Integer::from(1))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let rp = match Self::map_get(&map, Value::Integer(Integer::from(2))) {
            Some(Value::Map(rp)) => rp,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };
        let rp_id = match Self::map_get(rp, Value::Text("id".into())) {
            Some(Value::Text(text)) => text.clone(),
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let user = match Self::map_get(&map, Value::Integer(Integer::from(3))) {
            Some(Value::Map(user)) => user,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };
        let user_id = match Self::map_get(user, Value::Text("id".into())) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };
        let user_name = Self::map_get(user, Value::Text("name".into())).and_then(|v| match v {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        });
        let user_display_name =
            Self::map_get(user, Value::Text("displayName".into())).and_then(|v| match v {
                Value::Text(text) => Some(text.clone()),
                _ => None,
            });

        let params = match Self::map_get(&map, Value::Integer(Integer::from(4))) {
            Some(Value::Array(params)) => params,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let mut selected_alg = None;
        for entry in params {
            let Value::Map(param_map) = entry else {
                return Err(CTAP2_ERR_INVALID_CBOR);
            };
            let Some(Value::Integer(alg_value)) =
                Self::map_get(param_map, Value::Text("alg".into()))
            else {
                continue;
            };
            let alg_i128: i128 = alg_value.clone().into();
            if let Ok(alg) = CoseAlg::try_from(alg_i128 as i32) {
                selected_alg = Some(alg);
                break;
            }
        }
        let alg = selected_alg.ok_or(CTAP2_ERR_UNSUPPORTED_ALGORITHM)?;

        if let Some(Value::Array(exclude)) = Self::map_get(&map, Value::Integer(Integer::from(5))) {
            let credentials = self.load_credentials()?;
            for descriptor in exclude {
                let Value::Map(descriptor_map) = descriptor else {
                    continue;
                };
                let Some(Value::Bytes(id)) =
                    Self::map_get(descriptor_map, Value::Text("id".into()))
                else {
                    continue;
                };
                if credentials.iter().any(|c| c.credential_id == *id) {
                    return Err(CTAP2_ERR_CREDENTIAL_EXCLUDED);
                }
            }
        }

        let mut hmac_secret_requested = false;
        let mut cred_protect_requested: Option<u8> = None;

        if let Some(value) = Self::map_get(&map, Value::Integer(Integer::from(6))) {
            let Value::Map(extension_map) = value else {
                return Err(CTAP2_ERR_INVALID_CBOR);
            };
            for (key, value) in extension_map.iter() {
                match key {
                    Value::Text(text) if text == "hmac-secret" => match value {
                        Value::Bool(flag) => {
                            hmac_secret_requested = *flag;
                        }
                        _ => return Err(CTAP2_ERR_INVALID_CBOR),
                    },
                    Value::Text(text) if text == "credProtect" => {
                        let policy_value = match value {
                            Value::Integer(int) => {
                                let int_value: i128 = int.clone().into();
                                if int_value < 0 || int_value > u8::MAX as i128 {
                                    return Err(CTAP2_ERR_INVALID_OPTION);
                                }
                                int_value as u8
                            }
                            _ => return Err(CTAP2_ERR_INVALID_CBOR),
                        };
                        match policy_value {
                            1 | 2 | 3 => cred_protect_requested = Some(policy_value),
                            _ => return Err(CTAP2_ERR_INVALID_OPTION),
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut uv_requested = false;
        if let Some(Value::Map(options)) = Self::map_get(&map, Value::Integer(Integer::from(7))) {
            if let Some(Value::Bool(false)) = Self::map_get(options, Value::Text("up".into())) {
                return Err(CTAP2_ERR_INVALID_OPTION);
            }
            if let Some(Value::Bool(uv)) = Self::map_get(options, Value::Text("uv".into())) {
                if *uv {
                    uv_requested = true;
                }
            }
        }

        let pin_uv_auth_param = match Self::map_get(&map, Value::Integer(Integer::from(8))) {
            Some(Value::Bytes(bytes)) => Some(bytes.clone()),
            Some(_) => return Err(CTAP2_ERR_INVALID_CBOR),
            None => None,
        };

        let pin_uv_auth_protocol = match Self::map_get(&map, Value::Integer(Integer::from(9))) {
            Some(Value::Integer(int)) => Some(int.clone()),
            Some(_) => return Err(CTAP2_ERR_INVALID_CBOR),
            None => None,
        };

        if pin_uv_auth_param.is_some() != pin_uv_auth_protocol.is_some() {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }

        if uv_requested && pin_uv_auth_param.is_some() {
            return Err(CTAP2_ERR_INVALID_OPTION);
        }

        let mut uv_verified = false;

        if let (Some(pin_uv_auth_param), Some(protocol)) =
            (pin_uv_auth_param.as_ref(), pin_uv_auth_protocol)
        {
            let value: i128 = protocol.into();
            Self::ensure_supported_pin_uv_protocol(value)?;
            if pin_uv_auth_param.len() != 16 && pin_uv_auth_param.len() != 32 {
                return Err(CTAP2_ERR_PIN_AUTH_INVALID);
            }

            let mut token = self
                .pin_state
                .pin_uv_auth_token()
                .ok_or(CTAP2_ERR_PIN_AUTH_INVALID)?;
            let mut mac = HmacSha256::new_from_slice(&token).map_err(|_| CTAP2_ERR_PROCESSING)?;
            mac.update(&client_hash);
            let computed = mac.finalize().into_bytes();
            uv_verified = match pin_uv_auth_param.len() {
                16 => computed[..16] == pin_uv_auth_param[..],
                32 => computed[..32] == pin_uv_auth_param[..],
                _ => false,
            };
            token.zeroize();
            if !uv_verified {
                return Err(CTAP2_ERR_PIN_AUTH_INVALID);
            }
        }

        if uv_verified {
            self.ensure_pin_token_permission_for_rp(PIN_PERMISSION_MC, &rp_id)?;
        }

        let cred_protect_value = cred_protect_requested.unwrap_or(1);

        let (cose_key, secret_key) = create_credential(alg);
        let secret_key_bytes = secret_key.to_bytes();
        let credential_id_bytes = syscall!(self.client.random_bytes(32)).bytes;
        let credential_id = credential_id_bytes.to_vec();

        let cred_random_with_uv_bytes = syscall!(self.client.random_bytes(32)).bytes;
        if cred_random_with_uv_bytes.len() != 32 {
            return Err(CTAP2_ERR_PROCESSING);
        }
        let cred_random_without_uv_bytes = syscall!(self.client.random_bytes(32)).bytes;
        if cred_random_without_uv_bytes.len() != 32 {
            return Err(CTAP2_ERR_PROCESSING);
        }

        let cred_random_with_uv = cred_random_with_uv_bytes.to_vec();
        let cred_random_without_uv = cred_random_without_uv_bytes.to_vec();

        let mut credentials = self.load_credentials()?;
        let initial_sign_count = 0;
        credentials.push(StoredCredential {
            rp_id: rp_id.clone(),
            user_id: user_id.clone(),
            user_name,
            user_display_name,
            alg: alg as i32,
            credential_id: credential_id.clone(),
            public_key: cose_key.clone(),
            secret_key: secret_key_bytes.clone(),
            cred_random_with_uv: Some(cred_random_with_uv.clone()),
            cred_random_without_uv: Some(cred_random_without_uv.clone()),
            cred_protect: Some(cred_protect_value),
            sign_count: initial_sign_count,
        });
        self.save_credentials(&credentials)?;

        let mut extension_entries = Vec::new();
        if hmac_secret_requested {
            extension_entries.push((Value::Text("hmac-secret".into()), Value::Bool(true)));
        }
        if cred_protect_requested.is_some() {
            extension_entries.push((
                Value::Text("credProtect".into()),
                Value::Integer(Integer::from(cred_protect_value as u64)),
            ));
        }
        let extension_bytes = if extension_entries.is_empty() {
            None
        } else {
            let map = canonical_map(extension_entries);
            let mut encoded = Vec::new();
            into_writer(&map, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
            Some(encoded)
        };

        let auth_data = self.attested_auth_data(
            &rp_id,
            &credential_id,
            &cose_key,
            uv_verified,
            initial_sign_count,
            extension_bytes.as_deref(),
        );
        let (attestation_format, att_stmt) = if self.suppress_attestation {
            (Value::Text("none".into()), Value::Map(Vec::new()))
        } else {
            let attestation_result = self.attestation_signature(&auth_data, &client_hash)?;
            let att_stmt = if let Some((signature, certificate_chain)) = attestation_result {
                let entries = vec![
                    (
                        Value::Text("alg".into()),
                        Value::Integer(Integer::from(COSE_ALG_ES256)),
                    ),
                    (Value::Text("sig".into()), Value::Bytes(signature)),
                    (
                        Value::Text("x5c".into()),
                        Value::Array(certificate_chain.into_iter().map(Value::Bytes).collect()),
                    ),
                ];
                canonical_map(entries)
            } else {
                let signature = sign_challenge(alg, &secret_key, &auth_data, &client_hash);
                canonical_map(vec![
                    (
                        Value::Text("alg".into()),
                        Value::Integer(Integer::from(alg as i32)),
                    ),
                    (Value::Text("sig".into()), Value::Bytes(signature)),
                ])
            };
            (Value::Text("packed".into()), att_stmt)
        };

        let mut response_map = vec![
            (Value::Integer(Integer::from(1)), attestation_format),
            (
                Value::Integer(Integer::from(2)),
                Value::Bytes(auth_data.clone()),
            ),
            (Value::Integer(Integer::from(3)), att_stmt),
        ];

        canonical_sort(&mut response_map);
        let mut encoded = Vec::new();
        into_writer(&Value::Map(response_map), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    fn handle_get_assertion(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let request: Value = from_reader(payload).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        let map = match request {
            Value::Map(map) => map,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let rp_id = match Self::map_get(&map, Value::Integer(Integer::from(1))) {
            Some(Value::Text(text)) => text.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let client_hash = match Self::map_get(&map, Value::Integer(Integer::from(2))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let allow_list = match Self::map_get(&map, Value::Integer(Integer::from(3))) {
            Some(Value::Array(list)) => Some(list.clone()),
            _ => None,
        };

        let mut hmac_secret_request: Option<HmacSecretRequest> = None;
        if let Some(value) = Self::map_get(&map, Value::Integer(Integer::from(4))) {
            let Value::Map(extension_map) = value else {
                return Err(CTAP2_ERR_INVALID_CBOR);
            };
            for (key, value) in extension_map.iter() {
                if let Value::Text(text) = key {
                    if text == "hmac-secret" {
                        let Value::Map(params) = value else {
                            return Err(CTAP2_ERR_INVALID_CBOR);
                        };
                        let key_agreement =
                            match Self::map_get(params, Value::Integer(Integer::from(1))) {
                                Some(Value::Map(entries)) => entries.clone(),
                                _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
                            };
                        let salt_enc = match Self::map_get(params, Value::Integer(Integer::from(2)))
                        {
                            Some(Value::Bytes(bytes)) => bytes.clone(),
                            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
                        };
                        let salt_auth =
                            match Self::map_get(params, Value::Integer(Integer::from(3))) {
                                Some(Value::Bytes(bytes)) => bytes.clone(),
                                _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
                            };
                        if salt_auth.len() != 16 {
                            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
                        }
                        let protocol = match Self::map_get(params, Value::Integer(Integer::from(4)))
                        {
                            Some(Value::Integer(int)) => {
                                let value: i128 = int.clone().into();
                                PinProtocol::from_identifier(value)?
                            }
                            Some(_) => return Err(CTAP2_ERR_PIN_AUTH_INVALID),
                            None => PinProtocol::Classic(ClassicPinProtocol::V2),
                        };
                        hmac_secret_request = Some(HmacSecretRequest {
                            key_agreement,
                            salt_enc,
                            salt_auth,
                            protocol,
                        });
                    }
                }
            }
        }

        let mut uv_requested = false;
        if let Some(Value::Map(options)) = Self::map_get(&map, Value::Integer(Integer::from(5))) {
            if let Some(Value::Bool(false)) = Self::map_get(options, Value::Text("up".into())) {
                return Err(CTAP2_ERR_INVALID_OPTION);
            }
            if let Some(Value::Bool(uv)) = Self::map_get(options, Value::Text("uv".into())) {
                uv_requested = *uv;
            }
        }

        let pin_uv_auth_param = match Self::map_get(&map, Value::Integer(Integer::from(6))) {
            Some(Value::Bytes(bytes)) => Some(bytes.clone()),
            Some(_) => return Err(CTAP2_ERR_PIN_AUTH_INVALID),
            None => None,
        };

        let pin_uv_auth_protocol = match Self::map_get(&map, Value::Integer(Integer::from(7))) {
            Some(Value::Integer(int)) => Some(int.clone().into()),
            Some(_) => return Err(CTAP2_ERR_PIN_AUTH_INVALID),
            None => None,
        };

        let mut user_verified = false;
        match (pin_uv_auth_param.as_ref(), pin_uv_auth_protocol) {
            (Some(param), Some(protocol)) => {
                Self::ensure_supported_pin_uv_protocol(protocol)?;
                if param.len() != 16 && param.len() != 32 {
                    return Err(CTAP2_ERR_PIN_AUTH_INVALID);
                }
                let mut token = self
                    .pin_state
                    .pin_uv_auth_token()
                    .ok_or(CTAP2_ERR_PIN_AUTH_INVALID)?;
                let mut mac =
                    HmacSha256::new_from_slice(&token).map_err(|_| CTAP2_ERR_PROCESSING)?;
                mac.update(&client_hash);
                let computed = mac.finalize().into_bytes();
                let uv_verified = match param.len() {
                    16 => computed[..16] == param[..],
                    32 => computed[..32] == param[..],
                    _ => false,
                };
                token.zeroize();
                if !uv_verified {
                    return Err(CTAP2_ERR_PIN_AUTH_INVALID);
                }
                user_verified = true;
            }
            (None, None) => {
                if uv_requested {
                    return Err(CTAP2_ERR_INVALID_OPTION);
                }
            }
            _ => {
                return Err(CTAP2_ERR_MISSING_PARAMETER);
            }
        }

        if user_verified {
            self.ensure_pin_token_permission_for_rp(PIN_PERMISSION_GA, &rp_id)?;
        }

        let user_present = true;

        let mut credentials = self.load_credentials()?;

        let mut matching_indices: Vec<usize> = Vec::new();
        if let Some(list) = allow_list.as_ref() {
            for descriptor in list {
                let Value::Map(desc_map) = descriptor else {
                    continue;
                };
                let Some(Value::Bytes(id)) = Self::map_get(desc_map, Value::Text("id".into()))
                else {
                    continue;
                };
                if let Some(pos) = credentials.iter().position(|cred| {
                    cred.credential_id == *id
                        && cred.rp_id == rp_id
                        && Self::credential_allows(cred, user_verified, true)
                }) {
                    if !matching_indices.contains(&pos) {
                        matching_indices.push(pos);
                    }
                }
            }
            if matching_indices.is_empty() {
                return Err(CTAP2_ERR_NO_CREDENTIALS);
            }
        } else {
            for (index, cred) in credentials.iter().enumerate() {
                if cred.rp_id == rp_id && Self::credential_allows(cred, user_verified, false) {
                    matching_indices.push(index);
                }
            }
            if matching_indices.is_empty() {
                return Err(CTAP2_ERR_NO_CREDENTIALS);
            }
        }

        let chosen_index = matching_indices[0];
        let remaining_credentials: VecDeque<Vec<u8>> = matching_indices
            .iter()
            .skip(1)
            .map(|idx| credentials[*idx].credential_id.clone())
            .collect();
        let remaining_count = remaining_credentials.len();

        let (
            credential_id,
            user_id,
            user_name,
            user_display_name,
            secret_key_bytes,
            sign_count,
            alg,
            cred_random_with_uv,
            cred_random_without_uv,
        ) = {
            let credential = &mut credentials[chosen_index];
            let alg =
                CoseAlg::try_from(credential.alg).map_err(|_| CTAP2_ERR_UNSUPPORTED_ALGORITHM)?;
            let secret_key_bytes = credential.secret_key.clone();
            credential.sign_count = credential.sign_count.saturating_add(1);
            let sign_count = credential.sign_count;
            (
                credential.credential_id.clone(),
                credential.user_id.clone(),
                credential.user_name.clone(),
                credential.user_display_name.clone(),
                secret_key_bytes,
                sign_count,
                alg,
                credential.cred_random_with_uv.clone(),
                credential.cred_random_without_uv.clone(),
            )
        };

        let signing_key = credential_secret_from_bytes(alg, &secret_key_bytes)
            .map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut extension_entries = Vec::new();
        let mut pending_hmac_secret = None;
        if let Some(ref request) = hmac_secret_request {
            let (maybe_encrypted, pending_state) = self.process_hmac_secret_for_assertion(
                request,
                cred_random_with_uv.as_ref(),
                cred_random_without_uv.as_ref(),
                user_verified,
            )?;
            if let Some(encrypted) = maybe_encrypted {
                extension_entries
                    .push((Value::Text("hmac-secret".into()), Value::Bytes(encrypted)));
            }
            pending_hmac_secret = Some(pending_state);
        }

        let extension_bytes = if extension_entries.is_empty() {
            None
        } else {
            let map = canonical_map(extension_entries);
            let mut encoded = Vec::new();
            into_writer(&map, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
            Some(encoded)
        };

        let auth_data = self.assertion_auth_data(
            &rp_id,
            sign_count,
            user_present,
            user_verified,
            extension_bytes.as_deref(),
        );
        let signature = sign_challenge(alg, &signing_key, &auth_data, &client_hash);
        self.save_credentials(&credentials)?;

        if remaining_count != 0 {
            self.pending_assertion = Some(PendingAssertion {
                rp_id: rp_id.clone(),
                client_hash: client_hash.clone(),
                user_present,
                user_verified,
                remaining_credentials,
                hmac_secret: pending_hmac_secret,
            });
        }

        let credential_map = canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("id".into()),
                Value::Bytes(credential_id.clone()),
            ),
        ]);

        let mut user_entries = vec![(Value::Text("id".into()), Value::Bytes(user_id))];
        if let Some(name) = user_name {
            user_entries.push((Value::Text("name".into()), Value::Text(name)));
        }
        if let Some(display) = user_display_name {
            user_entries.push((Value::Text("displayName".into()), Value::Text(display)));
        }
        let user_map = canonical_map(user_entries);

        let mut response = vec![
            (Value::Integer(Integer::from(1)), credential_map),
            (Value::Integer(Integer::from(2)), Value::Bytes(auth_data)),
            (Value::Integer(Integer::from(3)), Value::Bytes(signature)),
            (Value::Integer(Integer::from(4)), user_map),
        ];

        if remaining_count != 0 {
            let total_count = 1 + remaining_count;
            response.push((
                Value::Integer(Integer::from(5)),
                Value::Integer(Integer::from(total_count as u64)),
            ));
        }

        canonical_sort(&mut response);
        let mut encoded = Vec::new();
        into_writer(&Value::Map(response), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    fn handle_get_next_assertion(&mut self) -> Result<Vec<u8>, u8> {
        let mut pending = self.pending_assertion.take().ok_or(CTAP2_ERR_NOT_ALLOWED)?;
        let credential_id = pending
            .remaining_credentials
            .pop_front()
            .ok_or(CTAP2_ERR_NOT_ALLOWED)?;

        let mut credentials = self.load_credentials()?;
        let credential = credentials
            .iter_mut()
            .find(|cred| cred.rp_id == pending.rp_id && cred.credential_id == credential_id)
            .ok_or(CTAP2_ERR_NO_CREDENTIALS)?;

        let alg = CoseAlg::try_from(credential.alg).map_err(|_| CTAP2_ERR_UNSUPPORTED_ALGORITHM)?;
        let secret_key_bytes = credential.secret_key.clone();
        credential.sign_count = credential.sign_count.saturating_add(1);
        let sign_count = credential.sign_count;
        let user_id = credential.user_id.clone();
        let user_name = credential.user_name.clone();
        let user_display_name = credential.user_display_name.clone();
        let cred_random_with_uv = credential.cred_random_with_uv.clone();
        let cred_random_without_uv = credential.cred_random_without_uv.clone();

        let signing_key = credential_secret_from_bytes(alg, &secret_key_bytes)
            .map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut extension_entries = Vec::new();
        if let Some(ref hmac_state) = pending.hmac_secret {
            let cred_random = if pending.user_verified {
                cred_random_with_uv.as_ref()
            } else {
                cred_random_without_uv.as_ref()
            };
            if let Some(encrypted) = hmac_state.encrypt_output_for(cred_random)? {
                extension_entries
                    .push((Value::Text("hmac-secret".into()), Value::Bytes(encrypted)));
            }
        }

        let extension_bytes = if extension_entries.is_empty() {
            None
        } else {
            let map = canonical_map(extension_entries);
            let mut encoded = Vec::new();
            into_writer(&map, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
            Some(encoded)
        };

        let auth_data = self.assertion_auth_data(
            &pending.rp_id,
            sign_count,
            pending.user_present,
            pending.user_verified,
            extension_bytes.as_deref(),
        );
        let signature = sign_challenge(
            alg,
            &signing_key,
            &auth_data,
            pending.client_hash.as_slice(),
        );
        self.save_credentials(&credentials)?;

        if !pending.remaining_credentials.is_empty() {
            self.pending_assertion = Some(pending);
        }

        let credential_map = canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (Value::Text("id".into()), Value::Bytes(credential_id)),
        ]);

        let mut user_entries = vec![(Value::Text("id".into()), Value::Bytes(user_id))];
        if let Some(name) = user_name {
            user_entries.push((Value::Text("name".into()), Value::Text(name)));
        }
        if let Some(display) = user_display_name {
            user_entries.push((Value::Text("displayName".into()), Value::Text(display)));
        }
        let user_map = canonical_map(user_entries);

        let mut response = vec![
            (Value::Integer(Integer::from(1)), credential_map),
            (Value::Integer(Integer::from(2)), Value::Bytes(auth_data)),
            (Value::Integer(Integer::from(3)), Value::Bytes(signature)),
            (Value::Integer(Integer::from(4)), user_map),
        ];

        canonical_sort(&mut response);
        let mut encoded = Vec::new();
        into_writer(&Value::Map(response), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }
}

impl<C, const N: usize> App<'_, N> for CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    fn commands(&self) -> &'static [Command] {
        &[Command::Cbor]
    }

    fn call(
        &mut self,
        command: Command,
        request: &[u8],
        response: &mut heapless_bytes::Bytes<N>,
    ) -> Result<(), Error> {
        match command {
            Command::Cbor => {
                if request.is_empty() {
                    return Err(Error::InvalidLength);
                }
                let subcommand = request[0];
                let payload = &request[1..];
                let result = match subcommand {
                    CTAP_CMD_GET_INFO => self.handle_get_info(),
                    CTAP_CMD_MAKE_CREDENTIAL => self.handle_make_credential(payload),
                    CTAP_CMD_GET_ASSERTION => self.handle_get_assertion(payload),
                    CTAP_CMD_GET_NEXT_ASSERTION => self.handle_get_next_assertion(),
                    CTAP_CMD_CLIENT_PIN => self.handle_client_pin(payload),
                    CTAP_CMD_CREDENTIAL_MANAGEMENT => self.handle_credential_management(payload),
                    _ => Err(CTAP2_ERR_INVALID_CBOR),
                };

                let message = match result {
                    Ok(bytes) => bytes,
                    Err(status) => vec![status],
                };

                response
                    .extend_from_slice(&message)
                    .map_err(|_| Error::InvalidLength)
            }
            _ => Err(Error::InvalidCommand),
        }
    }
}
