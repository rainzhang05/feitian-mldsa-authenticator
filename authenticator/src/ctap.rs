use crate::{
    cose_akp_key_map, cose_alg_for_kem_param_set, create_credential, decrypt_pin_block,
    derive_pin_uv_session_keys, encrypt_pin_block, sign_challenge, CoseAlg, PinUvSessionKeys,
    PIN_UV_AUTH_PROTOCOL_PQC,
};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use ctaphid_app::{App, Command, Error};
use hmac::{Hmac, Mac};
use p256::{
    ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, EncodedPoint,
    PublicKey as P256PublicKey, SecretKey as P256SecretKey,
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

use std::cmp::Ordering;
use trussed_mldsa::SecretKey;

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

const CTAP_CMD_MAKE_CREDENTIAL: u8 = 0x01;
const CTAP_CMD_GET_ASSERTION: u8 = 0x02;
const CTAP_CMD_GET_INFO: u8 = 0x04;
const CTAP_CMD_CLIENT_PIN: u8 = 0x06;

const CTAP2_OK: u8 = 0x00;
const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const CTAP2_ERR_INVALID_OPTION: u8 = 0x2C;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
const CTAP1_ERR_INVALID_PARAMETER: u8 = 0x2D;
const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
const CTAP2_ERR_PIN_BLOCKED: u8 = 0x32;
const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
const CTAP2_ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
const CTAP2_ERR_PROCESSING: u8 = 0x21;

const MAX_PIN_RETRIES: u8 = 8;
const MAX_PIN_FAILURES_BEFORE_BLOCK: u8 = 3;

type HmacSha256 = Hmac<Sha256>;

#[cfg(not(test))]
const CREDENTIAL_STORE_PATH: &str = "credentials.cbor";
const PIN_UV_AUTH_PROTOCOL_CLASSIC: i32 = 2;
const SUPPORTED_PIN_UV_PROTOCOLS: [i32; 2] = [
    PIN_UV_AUTH_PROTOCOL_PQC as i32,
    PIN_UV_AUTH_PROTOCOL_CLASSIC,
];

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
    sign_count: u32,
}

#[derive(Debug)]
struct PinState {
    pin_hash: Option<[u8; 16]>,
    pin_retries: u8,
    consecutive_failures: u8,
    pin_uv_auth_token: Option<[u8; 32]>,
}

impl PinState {
    const MIN_PIN_LENGTH: usize = 4;

    fn new() -> Self {
        Self {
            pin_hash: None,
            pin_retries: MAX_PIN_RETRIES,
            consecutive_failures: 0,
            pin_uv_auth_token: None,
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

    fn verify_pin_hash(&mut self, candidate: &[u8; 16]) -> Result<(), u8> {
        let Some(stored) = self.pin_hash else {
            return Err(CTAP2_ERR_PIN_NOT_SET);
        };
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
    }

    fn set_pin_uv_auth_token(&mut self, token: [u8; 32]) {
        self.clear_pin_uv_auth_token();
        self.pin_uv_auth_token = Some(token);
    }

    fn pin_uv_auth_token(&self) -> Option<[u8; 32]> {
        self.pin_uv_auth_token.as_ref().map(|token| {
            let mut copy = [0u8; 32];
            copy.copy_from_slice(token);
            copy
        })
    }
}

impl Drop for PinState {
    fn drop(&mut self) {
        self.clear_pin_uv_auth_token();
    }
}

#[derive(PartialEq, Eq)]
enum PinProtocol {
    Pqc,
    Classic,
}

enum PinProtocolSession {
    Pqc {
        param_set: KemParamSet,
        secret_key: KemSecretKey,
        public_key: Vec<u8>,
    },
    Classic {
        public_key: EncodedPoint,
        secret_key: P256SecretKey,
    },
}

impl PinProtocolSession {
    fn protocol(&self) -> PinProtocol {
        match self {
            PinProtocolSession::Pqc { .. } => PinProtocol::Pqc,
            PinProtocolSession::Classic { .. } => PinProtocol::Classic,
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
                let shared = trussed_mlkem::decapsulate(param_set, &secret_key, &ciphertext);
                let mut hasher = Sha256::new();
                hasher.update(&public_key);
                hasher.update(&ciphertext_bytes);
                let transcript_hash = hasher.finalize().to_vec();
                let keys = derive_pin_uv_session_keys(&shared.0, &transcript_hash);
                Ok((keys, transcript_hash))
            }
            PinProtocolSession::Classic {
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
                let keys = derive_pin_uv_session_keys(shared_bytes.as_ref(), &transcript_hash);
                Ok((keys, transcript_hash))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::{
        de::from_reader,
        ser::into_writer,
        value::{Integer, Value},
    };
    use core::task::Poll;
    use p256::{
        ecdh::diffie_hellman, EncodedPoint, PublicKey as P256PublicKey, SecretKey as P256SecretKey,
    };
    use sha2::{Digest, Sha256};
    use std::{collections::HashMap, convert::TryInto};
    use trussed::api::{reply, Reply, Request, RequestVariant};
    use trussed::client::{
        AttestationClient, CertificateClient, Client as TrussedClient, ClientResult, CounterClient,
        CryptoClient, FilesystemClient, FutureResult, ManagementClient, PollClient, UiClient,
    };
    use trussed::error::Error as TrussedError;
    use trussed::types::Message;
    use trussed_mlkem::{ParamSet as KemParamSet, SecretKey as KemSecretKey};
    use zeroize::Zeroize;

    #[derive(Default)]
    struct TestClient {
        pending: Option<Result<Reply, TrussedError>>,
        random_counter: u8,
        files: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl TestClient {
        fn new() -> Self {
            Self::default()
        }

        fn dispatch(&mut self, request: Request) -> Result<Reply, TrussedError> {
            match request {
                Request::RandomBytes(req) => {
                    let mut bytes = Vec::with_capacity(req.count);
                    for _ in 0..req.count {
                        bytes.push(self.random_counter);
                        self.random_counter = self.random_counter.wrapping_add(1);
                    }
                    let message = Message::from_slice(&bytes).expect("random bytes fit message");
                    Ok(Reply::from(reply::RandomBytes { bytes: message }))
                }
                Request::WriteFile(req) => {
                    let path_key = req.path.as_str().as_bytes().to_vec();
                    let data = req.data.as_slice().to_vec();
                    self.files.insert(path_key, data);
                    Ok(Reply::from(reply::WriteFile {}))
                }
                Request::ReadFile(req) => {
                    let path_key = req.path.as_str().as_bytes().to_vec();
                    if let Some(data) = self.files.get(&path_key) {
                        let message = Message::from_slice(data).expect("stored file fits message");
                        Ok(Reply::from(reply::ReadFile { data: message }))
                    } else {
                        Err(TrussedError::FilesystemReadFailure)
                    }
                }
                _ => Err(TrussedError::FunctionNotSupported),
            }
        }
    }

    impl PollClient for TestClient {
        fn request<Rq: RequestVariant>(&mut self, req: Rq) -> ClientResult<'_, Rq::Reply, Self> {
            assert!(self.pending.is_none(), "a request is already pending");
            let request: Request = req.into();
            self.pending = Some(self.dispatch(request));
            Ok(FutureResult::new(self))
        }

        fn poll(&mut self) -> Poll<Result<Reply, TrussedError>> {
            match self.pending.take() {
                Some(result) => Poll::Ready(result),
                None => Poll::Pending,
            }
        }
    }

    impl CryptoClient for TestClient {}
    impl FilesystemClient for TestClient {}
    impl AttestationClient for TestClient {}
    impl CertificateClient for TestClient {}
    impl CounterClient for TestClient {}
    impl ManagementClient for TestClient {}
    impl UiClient for TestClient {}
    impl TrussedClient for TestClient {}

    #[test]
    fn pqc_key_agreement_value_is_canonical_akp_map() {
        let public_key = vec![0x01, 0x02];
        let session = PinProtocolSession::Pqc {
            param_set: KemParamSet::MLKem512,
            secret_key: KemSecretKey(vec![]),
            public_key: public_key.clone(),
        };

        let value = session.key_agreement_value();
        let expected_alg = cose_alg_for_kem_param_set(KemParamSet::MLKem512);
        assert_eq!(value, cose_akp_key_map(expected_alg, &public_key));

        let mut encoded = Vec::new();
        into_writer(&value, &mut encoded).expect("encode COSE key agreement map");
        let expected = vec![0xA3, 0x01, 0x07, 0x03, 0x38, 0x6D, 0x20, 0x42, 0x01, 0x02];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn classic_key_agreement_value_is_canonical() {
        let secret_key = P256SecretKey::from_slice(&[0x13; 32]).expect("valid secret key");
        let public_key = secret_key.public_key().to_encoded_point(false);
        let session = PinProtocolSession::Classic {
            public_key: public_key.clone(),
            secret_key,
        };

        let value = session.key_agreement_value();
        let x = public_key
            .x()
            .expect("x coordinate present")
            .as_slice()
            .to_vec();
        let y = public_key
            .y()
            .expect("y coordinate present")
            .as_slice()
            .to_vec();

        let expected = canonical_map(vec![
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
        ]);

        assert_eq!(value, expected);

        let mut actual_bytes = Vec::new();
        into_writer(&value, &mut actual_bytes).expect("encode classic key agreement map");
        let mut expected_bytes = Vec::new();
        into_writer(&expected, &mut expected_bytes)
            .expect("encode expected classic key agreement map");
        assert_eq!(actual_bytes, expected_bytes);
    }

    #[test]
    fn get_info_response_encoding_is_canonical() {
        let aaguid = [0xAB; 16];
        let app = CtapApp::new(TestClient::new(), aaguid);

        let response = app.handle_get_info().expect("getInfo succeeds");
        assert_eq!(response[0], CTAP2_OK);

        let options = canonical_map(vec![
            (Value::Text("rk".into()), Value::Bool(true)),
            (Value::Text("uv".into()), Value::Bool(true)),
            (Value::Text("up".into()), Value::Bool(true)),
            (Value::Text("pinUvAuthToken".into()), Value::Bool(true)),
            (Value::Text("clientPin".into()), Value::Bool(true)),
        ]);

        let algorithms = Value::Array(vec![
            canonical_map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (
                    Value::Text("alg".into()),
                    Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
                ),
            ]),
            canonical_map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (
                    Value::Text("alg".into()),
                    Value::Integer(Integer::from(CoseAlg::MLDSA65 as i32)),
                ),
            ]),
            canonical_map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (
                    Value::Text("alg".into()),
                    Value::Integer(Integer::from(CoseAlg::MLDSA87 as i32)),
                ),
            ]),
        ]);

        let expected_map = canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Array(vec![Value::Text("FIDO_2_1".into())]),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Bytes(aaguid.to_vec()),
            ),
            (Value::Integer(Integer::from(4)), options),
            (
                Value::Integer(Integer::from(5)),
                Value::Integer(Integer::from(2048)),
            ),
            (
                Value::Integer(Integer::from(6)),
                Value::Array(vec![
                    Value::Integer(Integer::from(i32::from(PIN_UV_AUTH_PROTOCOL_PQC))),
                    Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
                ]),
            ),
            (
                Value::Integer(Integer::from(8)),
                Value::Integer(Integer::from(128)),
            ),
            (
                Value::Integer(Integer::from(9)),
                Value::Array(vec![Value::Text("usb".into())]),
            ),
            (Value::Integer(Integer::from(10)), algorithms),
            (
                Value::Integer(Integer::from(13)),
                Value::Integer(Integer::from(PinState::MIN_PIN_LENGTH as u64)),
            ),
        ]);

        let mut expected_bytes = Vec::new();
        into_writer(&expected_map, &mut expected_bytes).expect("encode expected getInfo map");
        assert_eq!(expected_bytes, &response[1..]);
    }

    #[test]
    fn get_assertion_response_encoding_is_canonical() {
        let mut app = CtapApp::new(TestClient::new(), [0x11; 16]);
        let rp_id = "example.com";
        let client_hash = vec![0x22; 32];
        let pin_token = [0x33; 32];
        app.pin_state.set_pin_uv_auth_token(pin_token);

        let mut mac = HmacSha256::new_from_slice(&pin_token).expect("valid token");
        mac.update(&client_hash);
        let pin_uv_auth_param: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();

        let user_id = vec![0x44, 0x55];
        let user_name = "user".to_string();
        let user_display = "User".to_string();
        let credential_id = vec![0xAA, 0xBB, 0xCC];
        let alg = CoseAlg::MLDSA44;
        let (public_key, secret_key) = create_credential(alg);

        app.stored_credentials.push(StoredCredential {
            rp_id: rp_id.to_string(),
            user_id: user_id.clone(),
            user_name: Some(user_name.clone()),
            user_display_name: Some(user_display.clone()),
            alg: alg as i32,
            credential_id: credential_id.clone(),
            public_key: public_key.clone(),
            secret_key: secret_key.0.clone(),
            sign_count: 0,
        });

        let request_map = canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Text(rp_id.to_string()),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Bytes(client_hash.clone()),
            ),
            (
                Value::Integer(Integer::from(6)),
                Value::Bytes(pin_uv_auth_param.clone()),
            ),
            (
                Value::Integer(Integer::from(7)),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
            ),
        ]);

        let mut payload = Vec::new();
        into_writer(&request_map, &mut payload).expect("serialize getAssertion request");
        let response = app
            .handle_get_assertion(&payload)
            .expect("getAssertion succeeds");
        assert_eq!(response[0], CTAP2_OK);

        let sign_count = app.stored_credentials[0].sign_count;
        assert_eq!(sign_count, 1);
        let Value::Map(entries) =
            from_reader(&response[1..]).expect("decode getAssertion response")
        else {
            panic!("response must be a map");
        };
        let mut credential_value = None;
        let mut auth_data_value = None;
        let mut signature_value = None;
        let mut user_value = None;
        for (key, value) in entries {
            match key {
                Value::Integer(int) => {
                    let label: i128 = int.into();
                    match label {
                        1 => credential_value = Some(value),
                        2 => auth_data_value = Some(value),
                        3 => signature_value = Some(value),
                        4 => user_value = Some(value),
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        let credential_map = match credential_value.expect("credential present") {
            Value::Map(map) => canonical_map(map),
            _ => panic!("credential must be a map"),
        };
        let auth_data = auth_data_value.expect("authData present");
        let auth_data_bytes = match &auth_data {
            Value::Bytes(bytes) => bytes,
            _ => panic!("authData must be bytes"),
        };
        assert_eq!(auth_data_bytes[32] & 0x01, 0x01);
        assert_eq!(auth_data_bytes[32] & 0x04, 0x04);
        let signature = signature_value.expect("signature present");
        let user_map = match user_value.expect("user present") {
            Value::Map(map) => canonical_map(map),
            _ => panic!("user must be a map"),
        };

        let expected_map = canonical_map(vec![
            (Value::Integer(Integer::from(1)), credential_map),
            (Value::Integer(Integer::from(2)), auth_data),
            (Value::Integer(Integer::from(3)), signature),
            (Value::Integer(Integer::from(4)), user_map),
        ]);

        let mut expected_bytes = Vec::new();
        into_writer(&expected_map, &mut expected_bytes).expect("encode expected getAssertion map");
        assert_eq!(expected_bytes, &response[1..]);
    }

    #[test]
    fn get_assertion_without_pin_uv_uses_presence_only() {
        let mut app = CtapApp::new(TestClient::new(), [0x11; 16]);
        let rp_id = "example.com";
        let client_hash = vec![0x22; 32];

        let user_id = vec![0x01, 0x02];
        let credential_id = vec![0xAA, 0xBB, 0xCC];
        let alg = CoseAlg::MLDSA44;
        let (public_key, secret_key) = create_credential(alg);

        app.stored_credentials.push(StoredCredential {
            rp_id: rp_id.to_string(),
            user_id: user_id.clone(),
            user_name: None,
            user_display_name: None,
            alg: alg as i32,
            credential_id: credential_id.clone(),
            public_key: public_key.clone(),
            secret_key: secret_key.0.clone(),
            sign_count: 7,
        });

        let request_map = canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Text(rp_id.to_string()),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Bytes(client_hash.clone()),
            ),
        ]);

        let mut payload = Vec::new();
        into_writer(&request_map, &mut payload).expect("serialize getAssertion request");
        let response = app
            .handle_get_assertion(&payload)
            .expect("getAssertion succeeds");
        assert_eq!(response[0], CTAP2_OK);

        let Value::Map(entries) = from_reader(&response[1..]).expect("decode getAssertion response") else {
            panic!("response must be a map");
        };

        let auth_data_bytes = entries
            .iter()
            .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
            .and_then(|(_, v)| match v {
                Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .expect("authData bytes present");

        assert_eq!(auth_data_bytes[32] & 0x01, 0x01);
        assert_eq!(auth_data_bytes[32] & 0x04, 0x00);

        let sign_count = app.stored_credentials[0].sign_count;
        assert_eq!(sign_count, 8);
    }

    #[test]
    fn get_assertion_with_invalid_pin_uv_auth_param_fails() {
        let mut app = CtapApp::new(TestClient::new(), [0x11; 16]);
        let rp_id = "example.com";
        let client_hash = vec![0x22; 32];
        let pin_token = [0x33; 32];
        app.pin_state.set_pin_uv_auth_token(pin_token);

        let user_id = vec![0x01, 0x02];
        let credential_id = vec![0xAA, 0xBB, 0xCC];
        let alg = CoseAlg::MLDSA44;
        let (public_key, secret_key) = create_credential(alg);

        app.stored_credentials.push(StoredCredential {
            rp_id: rp_id.to_string(),
            user_id: user_id.clone(),
            user_name: None,
            user_display_name: None,
            alg: alg as i32,
            credential_id: credential_id.clone(),
            public_key: public_key.clone(),
            secret_key: secret_key.0.clone(),
            sign_count: 0,
        });

        let pin_uv_auth_param = vec![0xFF; 16];

        let request_map = canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Text(rp_id.to_string()),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Bytes(client_hash.clone()),
            ),
            (
                Value::Integer(Integer::from(6)),
                Value::Bytes(pin_uv_auth_param),
            ),
            (
                Value::Integer(Integer::from(7)),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
            ),
        ]);

        let mut payload = Vec::new();
        into_writer(&request_map, &mut payload).expect("serialize getAssertion request");
        let result = app.handle_get_assertion(&payload);
        assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID));
    }

    fn request_classic_key_agreement(app: &mut CtapApp<TestClient>) -> Vec<(Value, Value)> {
        let request = canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Integer(Integer::from(0x02)),
            ),
        ]);
        let mut payload = Vec::new();
        into_writer(&request, &mut payload).expect("serialize key agreement request");
        let response = app
            .handle_client_pin(&payload)
            .expect("classic key agreement succeeds");
        assert_eq!(response[0], CTAP2_OK);
        let Value::Map(map) = from_reader(&response[1..]).expect("decode key agreement response")
        else {
            panic!("response must be a map");
        };
        match map
            .into_iter()
            .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        {
            Some((_, Value::Map(entries))) => entries,
            _ => panic!("missing key agreement data"),
        }
    }

    fn extract_coordinate(entries: &[(Value, Value)], label: i32) -> Vec<u8> {
        entries
            .iter()
            .find(|(k, _)| *k == Value::Integer(Integer::from(label)))
            .and_then(|(_, v)| match v {
                Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .expect("coordinate is present")
    }

    fn authenticator_public_key(entries: &[(Value, Value)]) -> P256PublicKey {
        let x = extract_coordinate(entries, -2);
        let y = extract_coordinate(entries, -3);
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        let mut encoded = [0u8; 65];
        encoded[0] = 0x04;
        encoded[1..33].copy_from_slice(&x);
        encoded[33..65].copy_from_slice(&y);
        P256PublicKey::from_sec1_bytes(&encoded).expect("authenticator public key is valid")
    }

    fn classic_platform_key_entries(point: &EncodedPoint) -> Vec<(Value, Value)> {
        let x_field = point.x().expect("x coordinate present");
        let x_slice: &[u8] = x_field.as_ref();
        let x = x_slice.to_vec();
        let y_field = point.y().expect("y coordinate present");
        let y_slice: &[u8] = y_field.as_ref();
        let y = y_slice.to_vec();
        let mut entries = vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
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
        ];
        canonical_sort(&mut entries);
        entries
    }

    fn derive_classic_session(
        auth_entries: &[(Value, Value)],
        platform_secret: &P256SecretKey,
    ) -> (PinUvSessionKeys, Vec<u8>, Vec<(Value, Value)>) {
        let auth_public = authenticator_public_key(auth_entries);
        let platform_public = platform_secret.public_key().to_encoded_point(false);
        let shared = diffie_hellman(platform_secret.to_nonzero_scalar(), auth_public.as_affine());
        let auth_encoded = auth_public.to_encoded_point(false);
        let mut hasher = Sha256::new();
        hasher.update(auth_encoded.as_bytes());
        hasher.update(platform_public.as_bytes());
        let transcript_hash = hasher.finalize().to_vec();
        let shared_bytes = shared.raw_secret_bytes();
        let keys = crate::derive_pin_uv_session_keys(shared_bytes.as_ref(), &transcript_hash);
        let platform_entries = classic_platform_key_entries(&platform_public);
        (keys, transcript_hash, platform_entries)
    }

    #[test]
    fn classic_pin_uv_protocol_flow() {
        let mut app = CtapApp::new(TestClient::new(), [0xA5; 16]);
        let pin = b"123456";
        let nonce = [0u8; 12];

        // Set the initial PIN using the classic protocol.
        let auth_key_entries = request_classic_key_agreement(&mut app);
        let platform_secret = P256SecretKey::from_slice(&[0x11; 32]).expect("valid secret key");
        let (set_keys, set_transcript_hash, platform_entries) =
            derive_classic_session(&auth_key_entries, &platform_secret);
        let mut new_pin_block = [0u8; 64];
        new_pin_block[..pin.len()].copy_from_slice(pin);
        let new_pin_enc =
            crate::encrypt_pin_block(&set_keys, &nonce, &new_pin_block, &set_transcript_hash);
        new_pin_block.zeroize();
        let mut pin_mac = HmacSha256::new_from_slice(&set_keys.auth_key).expect("valid MAC key");
        pin_mac.update(&new_pin_enc);
        let pin_auth = pin_mac.finalize().into_bytes();
        let set_pin_request = canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Integer(Integer::from(0x03)),
            ),
            (
                Value::Integer(Integer::from(3)),
                canonical_map(platform_entries.clone()),
            ),
            (
                Value::Integer(Integer::from(4)),
                Value::Bytes(pin_auth[..16].to_vec()),
            ),
            (Value::Integer(Integer::from(5)), Value::Bytes(new_pin_enc)),
        ]);
        let mut payload = Vec::new();
        into_writer(&set_pin_request, &mut payload).expect("serialize setPin request");
        let response = app.handle_client_pin(&payload).expect("setPin succeeds");
        assert_eq!(response, vec![CTAP2_OK]);
        assert!(app.pin_state.is_set());

        // Retrieve the PIN/UV token using the classic protocol.
        let auth_key_entries = request_classic_key_agreement(&mut app);
        let platform_secret = P256SecretKey::from_slice(&[0x22; 32]).expect("valid secret key");
        let (token_keys, token_transcript_hash, platform_entries) =
            derive_classic_session(&auth_key_entries, &platform_secret);
        let mut hasher = Sha256::new();
        hasher.update(pin);
        let pin_digest = hasher.finalize();
        let pin_hash = &pin_digest[..16];
        let pin_hash_enc =
            crate::encrypt_pin_block(&token_keys, &nonce, pin_hash, &token_transcript_hash);
        let mut token_mac =
            HmacSha256::new_from_slice(&token_keys.auth_key).expect("valid MAC key");
        token_mac.update(&pin_hash_enc);
        let pin_hash_auth = token_mac.finalize().into_bytes();
        let get_token_request = canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Integer(Integer::from(0x05)),
            ),
            (
                Value::Integer(Integer::from(3)),
                canonical_map(platform_entries.clone()),
            ),
            (
                Value::Integer(Integer::from(4)),
                Value::Bytes(pin_hash_auth[..16].to_vec()),
            ),
            (
                Value::Integer(Integer::from(6)),
                Value::Bytes(pin_hash_enc.clone()),
            ),
        ]);
        let mut payload = Vec::new();
        into_writer(&get_token_request, &mut payload).expect("serialize getPinToken request");
        let response = app
            .handle_client_pin(&payload)
            .expect("getPinToken succeeds");
        assert_eq!(response[0], CTAP2_OK);
        let Value::Map(map) = from_reader(&response[1..]).expect("decode getPinToken response")
        else {
            panic!("response must be a map");
        };
        let encrypted_token = map
            .iter()
            .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
            .and_then(|(_, v)| match v {
                Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .expect("encrypted token present");
        let pin_uv_auth_token_vec = crate::decrypt_pin_block(
            &token_keys,
            &nonce,
            &encrypted_token,
            &token_transcript_hash,
        )
        .expect("token decrypts");
        assert_eq!(pin_uv_auth_token_vec.len(), 32);
        let pin_uv_auth_token: [u8; 32] = pin_uv_auth_token_vec
            .as_slice()
            .try_into()
            .expect("token length is 32");
        let stored_token = app
            .pin_state
            .pin_uv_auth_token()
            .expect("token stored in state");
        assert_eq!(stored_token, pin_uv_auth_token);

        // Make a credential using the classic protocol pinUvAuthParam.
        let client_data_hash_mc = vec![0xAA; 32];
        let mut mac = HmacSha256::new_from_slice(&pin_uv_auth_token).expect("valid token MAC");
        mac.update(&client_data_hash_mc);
        let pin_uv_auth_param_mc: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();
        let rp = canonical_map(vec![(
            Value::Text("id".into()),
            Value::Text("example.com".into()),
        )]);
        let user = canonical_map(vec![
            (Value::Text("id".into()), Value::Bytes(vec![0x01, 0x02])),
            (Value::Text("name".into()), Value::Text("example".into())),
            (
                Value::Text("displayName".into()),
                Value::Text("Example".into()),
            ),
        ]);
        let pub_key_params = Value::Array(vec![canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("alg".into()),
                Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
            ),
        ])]);
        let make_credential = canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Bytes(client_data_hash_mc.clone()),
            ),
            (Value::Integer(Integer::from(2)), rp),
            (Value::Integer(Integer::from(3)), user),
            (Value::Integer(Integer::from(4)), pub_key_params),
            (
                Value::Integer(Integer::from(8)),
                Value::Bytes(pin_uv_auth_param_mc.clone()),
            ),
            (
                Value::Integer(Integer::from(9)),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
            ),
        ]);
        if let Value::Map(entries) = &make_credential {
            let protocol = entries
                .iter()
                .find(|(k, _)| *k == Value::Integer(Integer::from(9)))
                .and_then(|(_, v)| match v {
                    Value::Integer(int) => Some(int.clone()),
                    _ => None,
                })
                .expect("protocol present");
            let protocol_value: i128 = protocol.into();
            assert_eq!(
                protocol_value,
                i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC),
                "protocol value matches"
            );
        }
        let mut payload = Vec::new();
        into_writer(&make_credential, &mut payload).expect("serialize makeCredential request");
        let response = app
            .handle_make_credential(&payload)
            .expect("makeCredential succeeds");
        assert_eq!(response[0], CTAP2_OK);

        // Use the stored token to get an assertion via the classic protocol path.
        let client_data_hash_ga = vec![0xBB; 32];
        let mut mac = HmacSha256::new_from_slice(&pin_uv_auth_token).expect("valid token MAC");
        mac.update(&client_data_hash_ga);
        let pin_uv_auth_param_ga: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();
        let get_assertion = canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Text("example.com".into()),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Bytes(client_data_hash_ga.clone()),
            ),
            (
                Value::Integer(Integer::from(6)),
                Value::Bytes(pin_uv_auth_param_ga.clone()),
            ),
            (
                Value::Integer(Integer::from(7)),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
            ),
        ]);
        let mut payload = Vec::new();
        into_writer(&get_assertion, &mut payload).expect("serialize getAssertion request");
        let response = app
            .handle_get_assertion(&payload)
            .expect("getAssertion succeeds");
        assert_eq!(response[0], CTAP2_OK);
        assert!(app.pin_state.pin_uv_auth_token().is_some());
    }
}

pub struct CtapApp<C> {
    client: C,
    aaguid: [u8; 16],
    pin_state: PinState,
    pin_protocol_session: Option<PinProtocolSession>,
    platform_declined_pqc: bool,
    #[cfg(test)]
    stored_credentials: Vec<StoredCredential>,
}

impl<C> CtapApp<C> {
    pub fn new(client: C, aaguid: [u8; 16]) -> Self {
        Self {
            client,
            aaguid,
            pin_state: PinState::new(),
            pin_protocol_session: None,
            platform_declined_pqc: false,
            #[cfg(test)]
            stored_credentials: Vec::new(),
        }
    }
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    fn verify_pin_auth(keys: &PinUvSessionKeys, data: &[u8], provided: &[u8]) -> Result<(), u8> {
        let mut mac =
            HmacSha256::new_from_slice(&keys.auth_key).map_err(|_| CTAP2_ERR_PROCESSING)?;
        mac.update(data);
        let result = mac.finalize().into_bytes();
        if provided.len() != 16 {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if result[..16] == provided[..16] {
            Ok(())
        } else {
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    fn decrypt_pin_block_checked(
        keys: &PinUvSessionKeys,
        transcript_hash: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, u8> {
        if ciphertext.len() < 16 {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        let nonce = [0u8; 12];
        decrypt_pin_block(keys, &nonce, ciphertext, transcript_hash)
            .map_err(|_| CTAP2_ERR_PIN_AUTH_INVALID)
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

    fn requested_pin_protocol(&mut self, map: &[(Value, Value)]) -> Result<PinProtocol, u8> {
        if let Some(Value::Integer(int)) = Self::map_get(map, Value::Integer(Integer::from(1))) {
            let value: i128 = int.clone().into();
            match value {
                v if v == i128::from(PIN_UV_AUTH_PROTOCOL_PQC) => {
                    self.platform_declined_pqc = false;
                    Ok(PinProtocol::Pqc)
                }
                2 => {
                    self.platform_declined_pqc = true;
                    Ok(PinProtocol::Classic)
                }
                _ => Err(CTAP1_ERR_INVALID_PARAMETER),
            }
        } else if self.platform_declined_pqc {
            Ok(PinProtocol::Classic)
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
            PinProtocol::Classic => {
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
        Self::verify_pin_auth(&keys, &new_pin_enc, &pin_auth_param)?;
        let mut plaintext = Self::decrypt_pin_block_checked(&keys, &transcript_hash, &new_pin_enc)?;
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
        Self::verify_pin_auth(&keys, &auth_data, &pin_auth_param)?;

        let mut current_plain =
            Self::decrypt_pin_block_checked(&keys, &transcript_hash, &pin_hash_enc)?;
        let current_hash = Self::as_array::<16>(&current_plain)?;
        current_plain.zeroize();
        if let Err(err) = self.pin_state.verify_pin_hash(&current_hash) {
            return Err(err);
        }

        let mut new_pin_plain =
            Self::decrypt_pin_block_checked(&keys, &transcript_hash, &new_pin_enc)?;
        let mut new_pin = Self::extract_new_pin(&mut new_pin_plain)?;
        let hash = Self::hash_pin(&new_pin);
        new_pin.zeroize();
        self.pin_state.set_pin(hash);
        Ok(vec![CTAP2_OK])
    }

    fn client_pin_get_token(
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
        Self::verify_pin_auth(&keys, &pin_hash_enc, &pin_auth_param)?;

        let mut plain = Self::decrypt_pin_block_checked(&keys, &transcript_hash, &pin_hash_enc)?;
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
        let nonce = [0u8; 12];
        let encrypted = encrypt_pin_block(&keys, &nonce, &token, &transcript_hash);
        self.pin_state.set_pin_uv_auth_token(token);
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

    fn handle_client_pin(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
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
            0x02 => self.client_pin_get_key_agreement(protocol),
            0x03 => self.client_pin_set_pin(protocol, &map),
            0x04 => self.client_pin_change_pin(protocol, &map),
            0x05 | 0x09 => self.client_pin_get_token(protocol, &map),
            _ => Err(CTAP1_ERR_INVALID_PARAMETER),
        }
    }

    #[cfg(not(test))]
    fn store_path() -> Result<PathBuf, u8> {
        PathBuf::try_from(CREDENTIAL_STORE_PATH).map_err(|_| CTAP2_ERR_PROCESSING)
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

    fn attested_auth_data(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        cose_key: &[u8],
        uv: bool,
        sign_count: u32,
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
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data.extend_from_slice(&self.aaguid);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(cose_key);
        auth_data
    }

    fn assertion_auth_data(
        &self,
        rp_id: &str,
        sign_count: u32,
        user_present: bool,
        user_verified: bool,
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
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data
    }

    fn handle_get_info(&self) -> Result<Vec<u8>, u8> {
        let mut map = Vec::new();

        map.push((
            Value::Integer(Integer::from(1)),
            Value::Array(vec![Value::Text("FIDO_2_1".into())]),
        ));
        map.push((
            Value::Integer(Integer::from(3)),
            Value::Bytes(self.aaguid.to_vec()),
        ));

        let options = canonical_map(vec![
            (Value::Text("rk".into()), Value::Bool(true)),
            (Value::Text("uv".into()), Value::Bool(true)),
            (Value::Text("up".into()), Value::Bool(true)),
            (Value::Text("pinUvAuthToken".into()), Value::Bool(true)),
            (Value::Text("clientPin".into()), Value::Bool(true)),
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

        let algorithms = [-48, -49, -50]
            .into_iter()
            .map(|alg| {
                canonical_map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (
                        Value::Text("alg".into()),
                        Value::Integer(Integer::from(alg)),
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

    fn handle_make_credential(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
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

        let mut uv_requested = false;
        if let Some(Value::Map(options)) = Self::map_get(&map, Value::Integer(Integer::from(7))) {
            if let Some(Value::Bool(false)) = Self::map_get(options, Value::Text("up".into())) {
                return Err(CTAP2_ERR_INVALID_OPTION);
            }
            if let Some(Value::Bool(uv)) = Self::map_get(options, Value::Text("uv".into())) {
                if !uv {
                    return Err(CTAP2_ERR_INVALID_OPTION);
                }
                uv_requested = true;
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

        let (cose_key, secret_key) = create_credential(alg);
        let credential_id_bytes = syscall!(self.client.random_bytes(32)).bytes;
        let credential_id = credential_id_bytes.to_vec();

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
            secret_key: secret_key.0.clone(),
            sign_count: initial_sign_count,
        });
        self.save_credentials(&credentials)?;

        let auth_data = self.attested_auth_data(
            &rp_id,
            &credential_id,
            &cose_key,
            uv_verified,
            initial_sign_count,
        );
        let signature = sign_challenge(alg, &secret_key, &auth_data, &client_hash);
        let att_stmt = canonical_map(vec![
            (
                Value::Text("alg".into()),
                Value::Integer(Integer::from(alg as i32)),
            ),
            (Value::Text("sig".into()), Value::Bytes(signature)),
        ]);

        let mut response_map = vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Text("packed".into()),
            ),
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
                let mut mac = HmacSha256::new_from_slice(&token).map_err(|_| CTAP2_ERR_PROCESSING)?;
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

        let user_present = true;

        let mut credentials = self.load_credentials()?;

        let chosen_index = if let Some(list) = allow_list {
            let mut index = None;
            for descriptor in list {
                let Value::Map(desc_map) = descriptor else {
                    continue;
                };
                let Some(Value::Bytes(id)) = Self::map_get(&desc_map, Value::Text("id".into()))
                else {
                    continue;
                };
                if let Some(pos) = credentials
                    .iter()
                    .position(|cred| cred.credential_id == *id && cred.rp_id == rp_id)
                {
                    index = Some(pos);
                    break;
                }
            }
            index.ok_or(CTAP2_ERR_NO_CREDENTIALS)?
        } else {
            credentials
                .iter()
                .position(|cred| cred.rp_id == rp_id)
                .ok_or(CTAP2_ERR_NO_CREDENTIALS)?
        };

        let (
            credential_id,
            user_id,
            user_name,
            user_display_name,
            secret_key_bytes,
            sign_count,
            alg,
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
            )
        };

        let signing_key = SecretKey(secret_key_bytes.clone());
        let auth_data = self.assertion_auth_data(&rp_id, sign_count, user_present, user_verified);
        let signature = sign_challenge(alg, &signing_key, &auth_data, &client_hash);
        self.save_credentials(&credentials)?;

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
                    CTAP_CMD_CLIENT_PIN => self.handle_client_pin(payload),
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
