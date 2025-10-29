use super::*;
use crate::{credential_secret_from_bytes, CredentialSecretKey};
use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use core::task::Poll;
use p256::{
    ecdh::diffie_hellman,
    ecdsa::{
        signature::{Signer, Verifier},
        Signature as P256EcdsaSignature, SigningKey,
    },
    EncodedPoint, PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
        protocol: ClassicPinProtocol::V2,
        public_key: public_key.clone(),
        secret_key,
    };

    let value = session.key_agreement_value();
    let x = public_key
        .x()
        .expect("x coordinate present")
        .clone()
        .to_vec();
    let y = public_key
        .y()
        .expect("y coordinate present")
        .clone()
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
    into_writer(&expected, &mut expected_bytes).expect("encode expected classic key agreement map");
    assert_eq!(actual_bytes, expected_bytes);
}

fn assert_get_info_response(
    app: &mut CtapApp<TestClient>,
    aaguid: [u8; 16],
    expected_client_pin: bool,
) {
    let response = app.handle_get_info().expect("getInfo succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let options = canonical_map(vec![
        (Value::Text("rk".into()), Value::Bool(true)),
        (Value::Text("up".into()), Value::Bool(true)),
        (Value::Text("credMgmt".into()), Value::Bool(true)),
        (Value::Text("pinUvAuthToken".into()), Value::Bool(true)),
        (
            Value::Text("clientPin".into()),
            Value::Bool(expected_client_pin),
        ),
    ]);

    let extensions = Value::Array(vec![
        Value::Text("credProtect".into()),
        Value::Text("hmac-secret".into()),
    ]);

    let algorithms = Value::Array(vec![
        canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("alg".into()),
                Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
            ),
        ]),
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
            Value::Array(vec![
                Value::Text("FIDO_2_1".into()),
                Value::Text("FIDO_2_0".into()),
                Value::Text("U2F_V2".into()),
            ]),
        ),
        (Value::Integer(Integer::from(2)), extensions),
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
fn get_info_response_encoding_is_canonical_with_pin_unset() {
    let aaguid = [0xAB; 16];
    let mut app = CtapApp::new(TestClient::new(), aaguid);

    assert_get_info_response(&mut app, aaguid, false);
}

#[test]
fn get_info_response_encoding_is_canonical_with_pin_set() {
    let aaguid = [0xAB; 16];
    let mut app = CtapApp::new(TestClient::new(), aaguid);
    let pin_hash = [0x11; 16];
    app.pin_state.set_pin(pin_hash);

    assert_get_info_response(&mut app, aaguid, true);
}

#[test]
fn get_assertion_response_encoding_is_canonical() {
    let mut app = CtapApp::new(TestClient::new(), [0x11; 16]);
    let rp_id = "example.com";
    let client_hash = vec![0x22; 32];
    let pin_token = [0x33; 32];
    app.pin_state
        .set_pin_uv_auth_token(pin_token, PIN_PERMISSION_MC | PIN_PERMISSION_GA, None);

    let mut mac = HmacSha256::new_from_slice(&pin_token).expect("valid token");
    mac.update(&client_hash);
    let pin_uv_auth_param: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();

    let user_id = vec![0x44, 0x55];
    let user_name = "user".to_string();
    let user_display = "User".to_string();
    let credential_id = vec![0xAA, 0xBB, 0xCC];
    let alg = CoseAlg::MLDSA44;
    let (public_key, secret_key) = create_credential(alg);
    let secret_key_bytes = secret_key.to_bytes();

    app.stored_credentials.push(StoredCredential {
        rp_id: rp_id.to_string(),
        user_id: user_id.clone(),
        user_name: Some(user_name.clone()),
        user_display_name: Some(user_display.clone()),
        alg: alg as i32,
        credential_id: credential_id.clone(),
        public_key: public_key.clone(),
        secret_key: secret_key_bytes.clone(),
        cred_random_with_uv: Some(vec![0x10; 32]),
        cred_random_without_uv: Some(vec![0x20; 32]),
        cred_protect: Some(1),
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
    let Value::Map(entries) = from_reader(&response[1..]).expect("decode getAssertion response")
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
fn get_next_assertion_preserves_new_credentials() {
    let mut app = CtapApp::new(TestClient::new(), [0x55; 16]);
    let rp_id = "example.com";
    let client_hash = vec![0x66; 32];

    let (pk1, sk1) = create_credential(CoseAlg::MLDSA44);
    let sk1_bytes = sk1.to_bytes();
    app.stored_credentials.push(StoredCredential {
        rp_id: rp_id.to_string(),
        user_id: vec![0x01],
        user_name: Some("one".into()),
        user_display_name: Some("One".into()),
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xA1],
        public_key: pk1.clone(),
        secret_key: sk1_bytes.clone(),
        cred_random_with_uv: Some(vec![0x10; 32]),
        cred_random_without_uv: Some(vec![0x11; 32]),
        cred_protect: Some(1),
        sign_count: 0,
    });

    let (pk2, sk2) = create_credential(CoseAlg::MLDSA44);
    let sk2_bytes = sk2.to_bytes();
    app.stored_credentials.push(StoredCredential {
        rp_id: rp_id.to_string(),
        user_id: vec![0x02],
        user_name: Some("two".into()),
        user_display_name: Some("Two".into()),
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xA2],
        public_key: pk2.clone(),
        secret_key: sk2_bytes.clone(),
        cred_random_with_uv: Some(vec![0x12; 32]),
        cred_random_without_uv: Some(vec![0x13; 32]),
        cred_protect: Some(1),
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
    ]);

    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize getAssertion request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("getAssertion succeeds");
    assert_eq!(response[0], CTAP2_OK);
    assert!(app.pending_assertion.is_some());
    assert_eq!(app.stored_credentials[0].sign_count, 1);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode getAssertion response")
    else {
        panic!("response must be a map");
    };
    let mut total_credentials_value = None;
    for (key, value) in entries {
        if let Value::Integer(label) = key {
            if label == Integer::from(5) {
                total_credentials_value = Some(value);
            }
        }
    }
    let total_credentials = match total_credentials_value.expect("total credential count present") {
        Value::Integer(int) => {
            let count: i128 = int.into();
            count
        }
        _ => panic!("total credential count must be an integer"),
    };
    assert_eq!(total_credentials, 2);

    let (pk3, sk3) = create_credential(CoseAlg::MLDSA44);
    let sk3_bytes = sk3.to_bytes();
    app.stored_credentials.push(StoredCredential {
        rp_id: "new.example".into(),
        user_id: vec![0x03],
        user_name: Some("three".into()),
        user_display_name: None,
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xA3],
        public_key: pk3.clone(),
        secret_key: sk3_bytes.clone(),
        cred_random_with_uv: Some(vec![0x14; 32]),
        cred_random_without_uv: Some(vec![0x15; 32]),
        cred_protect: Some(1),
        sign_count: 0,
    });

    let next_response = app
        .handle_get_next_assertion()
        .expect("getNextAssertion succeeds");
    assert_eq!(next_response[0], CTAP2_OK);
    assert!(app.pending_assertion.is_none());
    assert_eq!(app.stored_credentials.len(), 3);
    assert!(app
        .stored_credentials
        .iter()
        .any(|cred| cred.credential_id == vec![0xA3]));
    let second = app
        .stored_credentials
        .iter()
        .find(|cred| cred.credential_id == vec![0xA2])
        .expect("second credential present");
    assert_eq!(second.sign_count, 1);

    let Value::Map(entries) =
        from_reader(&next_response[1..]).expect("decode getNextAssertion response")
    else {
        panic!("next response must be a map");
    };
    for (key, _) in entries {
        if let Value::Integer(label) = key {
            assert_ne!(
                label,
                Integer::from(5),
                "getNextAssertion must omit total count"
            );
        }
    }
}

#[test]
fn get_next_assertion_without_pending_fails() {
    let mut app = CtapApp::new(TestClient::new(), [0x77; 16]);
    assert_eq!(app.handle_get_next_assertion(), Err(CTAP2_ERR_NOT_ALLOWED));
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
    let secret_key_bytes = secret_key.to_bytes();

    app.stored_credentials.push(StoredCredential {
        rp_id: rp_id.to_string(),
        user_id: user_id.clone(),
        user_name: None,
        user_display_name: None,
        alg: alg as i32,
        credential_id: credential_id.clone(),
        public_key: public_key.clone(),
        secret_key: secret_key_bytes.clone(),
        cred_random_with_uv: Some(vec![0x30; 32]),
        cred_random_without_uv: Some(vec![0x40; 32]),
        cred_protect: Some(1),
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

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode getAssertion response")
    else {
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
    app.pin_state
        .set_pin_uv_auth_token(pin_token, PIN_PERMISSION_MC | PIN_PERMISSION_GA, None);

    let user_id = vec![0x01, 0x02];
    let credential_id = vec![0xAA, 0xBB, 0xCC];
    let alg = CoseAlg::MLDSA44;
    let (public_key, secret_key) = create_credential(alg);
    let secret_key_bytes = secret_key.to_bytes();

    app.stored_credentials.push(StoredCredential {
        rp_id: rp_id.to_string(),
        user_id: user_id.clone(),
        user_name: None,
        user_display_name: None,
        alg: alg as i32,
        credential_id: credential_id.clone(),
        public_key: public_key.clone(),
        secret_key: secret_key_bytes.clone(),
        cred_random_with_uv: Some(vec![0x50; 32]),
        cred_random_without_uv: Some(vec![0x60; 32]),
        cred_protect: Some(1),
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

#[test]
fn make_credential_includes_extensions() {
    let mut app = CtapApp::new(TestClient::new(), [0xAA; 16]);
    let client_hash = vec![0xBB; 32];
    let pin_token = [0xCC; 32];
    app.pin_state
        .set_pin_uv_auth_token(pin_token, PIN_PERMISSION_MC | PIN_PERMISSION_GA, None);

    let mut mac = HmacSha256::new_from_slice(&pin_token).expect("valid token MAC");
    mac.update(&client_hash);
    let pin_uv_auth_param: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();

    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![
        (Value::Text("id".into()), Value::Bytes(vec![0x01, 0x02])),
        (Value::Text("name".into()), Value::Text("user".into())),
    ]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);
    let extensions = canonical_map(vec![
        (Value::Text("hmac-secret".into()), Value::Bool(true)),
        (
            Value::Text("credProtect".into()),
            Value::Integer(Integer::from(3)),
        ),
    ]);

    let make_credential = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
        (Value::Integer(Integer::from(6)), extensions),
        (
            Value::Integer(Integer::from(8)),
            Value::Bytes(pin_uv_auth_param.clone()),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_credential, &mut payload).expect("serialize makeCredential request");
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let credential = &app.stored_credentials[0];
    assert_eq!(credential.cred_protect, Some(3));
    assert_eq!(
        credential
            .cred_random_with_uv
            .as_ref()
            .expect("credRandom with UV present")
            .len(),
        32
    );
    assert_eq!(
        credential
            .cred_random_without_uv
            .as_ref()
            .expect("credRandom without UV present")
            .len(),
        32
    );

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let auth_data = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData present");
    assert_eq!(auth_data[32] & 0x80, 0x80);

    let mut offset = 32 + 1 + 4; // rpId hash + flags + sign count
    offset += 16; // AAGUID
    offset += 2; // credential ID length field
    offset += credential.credential_id.len();
    offset += credential.public_key.len();

    let extension_bytes = &auth_data[offset..];
    let Value::Map(extension_map) = from_reader(extension_bytes).expect("decode extensions") else {
        panic!("extensions must be a map");
    };
    let hmac_value = extension_map
        .iter()
        .find(|(k, _)| *k == Value::Text("hmac-secret".into()))
        .and_then(|(_, v)| match v {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        })
        .expect("hmac-secret extension present");
    assert!(hmac_value);

    let cred_protect_value: i128 = extension_map
        .iter()
        .find(|(k, _)| *k == Value::Text("credProtect".into()))
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone().into()),
            _ => None,
        })
        .expect("credProtect extension present");
    assert_eq!(cred_protect_value, 3);
}

#[test]
fn make_credential_supports_es256() {
    let mut app = CtapApp::new(TestClient::new(), [0x01; 16]);
    let client_hash = vec![0x10; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0xAA]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
    ])]);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize makeCredential request");
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
    assert_eq!(response[0], CTAP2_OK);

    assert_eq!(app.stored_credentials.len(), 1);
    let credential = &app.stored_credentials[0];
    assert_eq!(credential.alg, CoseAlg::ES256 as i32);
    assert_eq!(credential.secret_key.len(), 32);

    let Value::Map(entries) =
        from_reader(credential.public_key.as_slice()).expect("decode ES256 COSE key")
    else {
        panic!("public key must be a map");
    };

    let mut kty = None;
    let mut alg = None;
    let mut crv = None;
    let mut x_len = None;
    let mut y_len = None;

    for (key, value) in entries {
        if let Value::Integer(label) = key {
            let label_value: i128 = label.clone().into();
            match label_value {
                1 => kty = Some(value),
                3 => alg = Some(value),
                -1 => crv = Some(value),
                -2 => {
                    if let Value::Bytes(bytes) = value {
                        x_len = Some(bytes.len());
                    }
                }
                -3 => {
                    if let Value::Bytes(bytes) = value {
                        y_len = Some(bytes.len());
                    }
                }
                _ => {}
            }
        }
    }

    assert_eq!(
        kty,
        Some(Value::Integer(Integer::from(2))),
        "kty must be EC2"
    );
    assert_eq!(
        alg,
        Some(Value::Integer(Integer::from(CoseAlg::ES256 as i32))),
        "alg must be ES256"
    );
    assert_eq!(
        crv,
        Some(Value::Integer(Integer::from(1))),
        "curve must be P-256"
    );
    assert_eq!(x_len, Some(32));
    assert_eq!(y_len, Some(32));

    let reconstructed =
        credential_secret_from_bytes(CoseAlg::ES256, credential.secret_key.as_slice())
            .expect("reconstruct ES256 secret key");
    match reconstructed {
        CredentialSecretKey::Es256(_) => {}
        _ => panic!("expected ES256 secret key variant"),
    }
}

#[test]
fn get_assertion_es256_signature_verifies() {
    let mut app = CtapApp::new(TestClient::new(), [0x02; 16]);
    let rp_id = "example.com";
    let client_hash = vec![0x99; 32];

    let (public_key, secret_key) = create_credential(CoseAlg::ES256);
    let verifying_key = match &secret_key {
        CredentialSecretKey::Es256(sk) => sk.verifying_key(),
        _ => panic!("expected ES256 secret key"),
    };
    let secret_key_bytes = secret_key.to_bytes();

    app.stored_credentials.push(StoredCredential {
        rp_id: rp_id.to_string(),
        user_id: vec![0x01],
        user_name: None,
        user_display_name: None,
        alg: CoseAlg::ES256 as i32,
        credential_id: vec![0xA1, 0xB2],
        public_key: public_key.clone(),
        secret_key: secret_key_bytes.clone(),
        cred_random_with_uv: None,
        cred_random_without_uv: None,
        cred_protect: Some(1),
        sign_count: 0,
    });

    let request = canonical_map(vec![
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
    into_writer(&request, &mut payload).expect("serialize getAssertion request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("getAssertion succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode getAssertion response")
    else {
        panic!("response must be a map");
    };

    let mut auth_data_bytes = None;
    let mut signature_bytes = None;
    for (key, value) in entries {
        if key == Value::Integer(Integer::from(2)) {
            if let Value::Bytes(bytes) = value {
                auth_data_bytes = Some(bytes);
            }
        } else if key == Value::Integer(Integer::from(3)) {
            if let Value::Bytes(bytes) = value {
                signature_bytes = Some(bytes);
            }
        }
    }

    let auth_data_bytes = auth_data_bytes.expect("authData present");
    let signature_bytes = signature_bytes.expect("signature present");

    let mut message = Vec::new();
    message.extend_from_slice(&auth_data_bytes);
    message.extend_from_slice(&client_hash);

    let signature =
        P256EcdsaSignature::from_der(&signature_bytes).expect("signature must be valid DER");
    verifying_key
        .verify(&message, &signature)
        .expect("ES256 signature verifies");
}

#[test]
fn make_credential_uses_attestation_certificate_when_available() {
    let mut app = CtapApp::new(TestClient::new(), [0xAB; 16]);
    let att_key_bytes = vec![0x13; 32];
    let secret = P256SecretKey::from_slice(&att_key_bytes).expect("valid attestation key");
    let certificate = vec![0x30, 0x82, 0x00, 0x01];
    app.attestation_private_key = Some(att_key_bytes.clone());
    app.attestation_certificate_chain = Some(vec![certificate.clone()]);

    let client_hash = vec![0x11; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0xAA]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);

    let make_credential = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_credential, &mut payload).expect("serialize makeCredential request");
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let auth_data = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData present");
    let att_stmt_entries = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(3)))
        .and_then(|(_, v)| match v {
            Value::Map(map) => Some(map.clone()),
            _ => None,
        })
        .expect("attStmt present");

    let alg_value = att_stmt_entries
        .iter()
        .find(|(k, _)| match k {
            Value::Text(text) => text == "alg",
            _ => false,
        })
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone()),
            _ => None,
        })
        .expect("alg value present");
    let alg_i128: i128 = alg_value.into();
    assert_eq!(alg_i128, i128::from(COSE_ALG_ES256));

    let signature_bytes = att_stmt_entries
        .iter()
        .find(|(k, _)| match k {
            Value::Text(text) => text == "sig",
            _ => false,
        })
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("sig value present");
    let cert_chain = att_stmt_entries
        .iter()
        .find(|(k, _)| match k {
            Value::Text(text) => text == "x5c",
            _ => false,
        })
        .and_then(|(_, v)| match v {
            Value::Array(values) => Some(values.clone()),
            _ => None,
        })
        .expect("x5c present");
    assert_eq!(cert_chain.len(), 1);
    assert_eq!(
        cert_chain[0],
        Value::Bytes(certificate.clone()),
        "certificate chain returned",
    );

    let signing_key = SigningKey::from(secret);
    let mut message = Vec::with_capacity(auth_data.len() + client_hash.len());
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(&client_hash);
    let expected_signature: P256EcdsaSignature = signing_key.sign(&message);
    let expected_der = expected_signature.to_der();
    assert_eq!(signature_bytes.as_slice(), expected_der.as_bytes());
}

#[test]
fn make_credential_self_attestation_without_attestation_key() {
    let mut app = CtapApp::new(TestClient::new(), [0xCD; 16]);
    let client_hash = vec![0x22; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x01]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);

    let make_credential = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_credential, &mut payload).expect("serialize makeCredential request");
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let fmt_value = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        .and_then(|(_, v)| match v {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        })
        .expect("fmt present");
    assert_eq!(fmt_value, "packed");
    let att_stmt_entries = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(3)))
        .and_then(|(_, v)| match v {
            Value::Map(map) => Some(map.clone()),
            _ => None,
        })
        .expect("attStmt present");

    assert!(
        att_stmt_entries.iter().all(|(k, _)| match k {
            Value::Text(text) => text != "x5c",
            _ => true,
        }),
        "x5c should be absent for self attestation",
    );

    let alg_value = att_stmt_entries
        .iter()
        .find(|(k, _)| match k {
            Value::Text(text) => text == "alg",
            _ => false,
        })
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone()),
            _ => None,
        })
        .expect("alg value present");
    let alg_i128: i128 = alg_value.into();
    assert_eq!(alg_i128, i128::from(CoseAlg::MLDSA44 as i32));

    let signature_bytes = att_stmt_entries
        .iter()
        .find(|(k, _)| match k {
            Value::Text(text) => text == "sig",
            _ => false,
        })
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("sig value present");
    assert!(!signature_bytes.is_empty());
}

#[test]
fn make_credential_can_suppress_attestation() {
    let mut app = CtapApp::new(TestClient::new(), [0xDD; 16]);
    app.suppress_attestation(true);

    let client_hash = vec![0x33; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x02]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);

    let make_credential = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_credential, &mut payload).expect("serialize makeCredential request");
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
    assert_eq!(response[0], CTAP2_OK);
    assert_eq!(app.stored_credentials.len(), 1);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let fmt_value = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        .and_then(|(_, v)| match v {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        })
        .expect("fmt present");
    assert_eq!(fmt_value, "none");

    let auth_data = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData present");
    assert!(!auth_data.is_empty());

    let att_stmt_entries = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(3)))
        .and_then(|(_, v)| match v {
            Value::Map(map) => Some(map.clone()),
            _ => None,
        })
        .expect("attStmt present");
    assert!(att_stmt_entries.is_empty());
}

#[test]
fn get_assertion_produces_hmac_secret_output() {
    let mut app = CtapApp::new(TestClient::new(), [0x42; 16]);
    let pin = b"1234";
    let mut hasher = Sha256::new();
    hasher.update(pin);
    let digest = hasher.finalize();
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&digest[..16]);
    app.pin_state.set_pin(pin_hash);

    let pin_token = [0x55; 32];
    app.pin_state
        .set_pin_uv_auth_token(pin_token, PIN_PERMISSION_MC | PIN_PERMISSION_GA, None);

    let client_hash = vec![0x77; 32];
    let mut mac = HmacSha256::new_from_slice(&pin_token).expect("valid token MAC");
    mac.update(&client_hash);
    let pin_uv_auth_param: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();

    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Bytes(vec![0x01, 0x02]),
    )]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);
    let extensions = canonical_map(vec![(Value::Text("hmac-secret".into()), Value::Bool(true))]);

    let make_credential = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
        (Value::Integer(Integer::from(6)), extensions),
        (
            Value::Integer(Integer::from(8)),
            Value::Bytes(pin_uv_auth_param.clone()),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_credential, &mut payload).expect("serialize makeCredential request");
    app.handle_make_credential(&payload)
        .expect("makeCredential succeeds");

    let auth_entries = request_classic_key_agreement(&mut app, ClassicPinProtocol::V2);
    let platform_secret = P256SecretKey::from_slice(&[0x23; 32]).expect("valid secret key");
    let (session_keys, _transcript_hash, platform_entries) =
        derive_classic_session(ClassicPinProtocol::V2, &auth_entries, &platform_secret);

    let salt = vec![0x99; 32];
    let salt_enc = encrypt_shared_secret(&session_keys.encryption_key, &salt)
        .expect("salt encryption succeeds");
    let mut salt_mac = HmacSha256::new_from_slice(&session_keys.auth_key).expect("valid MAC key");
    salt_mac.update(&salt_enc);
    let salt_auth: Vec<u8> = salt_mac.finalize().into_bytes()[..16].to_vec();

    let client_hash_assert = vec![0x88; 32];
    let mut mac = HmacSha256::new_from_slice(&pin_token).expect("valid token MAC");
    mac.update(&client_hash_assert);
    let pin_uv_auth_param_assert: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();

    let hmac_extension = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            canonical_map(platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(salt_enc.clone()),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Bytes(salt_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);
    let extensions = canonical_map(vec![(Value::Text("hmac-secret".into()), hmac_extension)]);

    let get_assertion = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text("example.com".into()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(client_hash_assert.clone()),
        ),
        (Value::Integer(Integer::from(4)), extensions),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_uv_auth_param_assert.clone()),
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

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let auth_data = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData present");
    assert_eq!(auth_data[32] & 0x80, 0x80);

    let extension_bytes = &auth_data[32 + 1 + 4..];
    let Value::Map(extension_map) = from_reader(extension_bytes).expect("decode extensions") else {
        panic!("extensions must be a map");
    };
    let encrypted_output = extension_map
        .iter()
        .find(|(k, _)| *k == Value::Text("hmac-secret".into()))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("encrypted output present");

    let decrypted = decrypt_shared_secret(&session_keys.encryption_key, &encrypted_output)
        .expect("decrypt hmac-secret output");
    assert_eq!(decrypted.len(), 32);

    let credential = &app.stored_credentials[0];
    let random = credential
        .cred_random_with_uv
        .as_ref()
        .expect("credRandom with UV present");
    let mut expected_mac =
        HmacSha256::new_from_slice(random).expect("valid MAC key for credential");
    expected_mac.update(&salt);
    let expected = expected_mac.finalize().into_bytes();
    assert_eq!(&decrypted[..], &expected[..]);
}

#[test]
fn make_credential_requires_mc_permission() {
    let mut app = CtapApp::new(TestClient::new(), [0x51; 16]);
    let token = [0xAA; 32];
    app.pin_state
        .set_pin_uv_auth_token(token, PIN_PERMISSION_GA, None);

    let client_hash = vec![0xBB; 32];
    let mut mac = HmacSha256::new_from_slice(&token).expect("valid MAC key");
    mac.update(&client_hash);
    let pin_uv_auth_param: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();

    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x01]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
        (
            Value::Integer(Integer::from(8)),
            Value::Bytes(pin_uv_auth_param),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize makeCredential request");
    let result = app.handle_make_credential(&payload);
    assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID));
}

#[test]
fn get_assertion_rejects_mismatched_rp_binding() {
    let mut app = CtapApp::new(TestClient::new(), [0x52; 16]);
    let token = [0xAB; 32];
    app.pin_state
        .set_pin_uv_auth_token(token, PIN_PERMISSION_GA, Some("other.com".into()));

    let client_hash = vec![0xCC; 32];
    let mut mac = HmacSha256::new_from_slice(&token).expect("valid MAC key");
    mac.update(&client_hash);
    let pin_uv_auth_param: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();

    let credential_id = vec![0xAA, 0xBB];
    let alg = CoseAlg::MLDSA44;
    let (public_key, secret_key) = create_credential(alg);
    let secret_key_bytes = secret_key.to_bytes();
    app.stored_credentials.push(StoredCredential {
        rp_id: "example.com".into(),
        user_id: vec![0x01],
        user_name: None,
        user_display_name: None,
        alg: alg as i32,
        credential_id: credential_id.clone(),
        public_key: public_key.clone(),
        secret_key: secret_key_bytes.clone(),
        cred_random_with_uv: None,
        cred_random_without_uv: None,
        cred_protect: Some(1),
        sign_count: 0,
    });

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text("example.com".into()),
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
    into_writer(&request, &mut payload).expect("serialize getAssertion request");
    let result = app.handle_get_assertion(&payload);
    assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID));
}

#[test]
fn cred_protect_enforced_for_user_verification() {
    let mut app = CtapApp::new(TestClient::new(), [0x33; 16]);
    let rp_id = "example.com";
    let client_hash = vec![0x55; 32];

    app.stored_credentials.push(StoredCredential {
        rp_id: rp_id.to_string(),
        user_id: vec![0x01],
        user_name: None,
        user_display_name: None,
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xAA],
        public_key: vec![0x01, 0x02, 0x03],
        secret_key: vec![0x10; 32],
        cred_random_with_uv: Some(vec![0x11; 32]),
        cred_random_without_uv: Some(vec![0x12; 32]),
        cred_protect: Some(3),
        sign_count: 0,
    });
    app.stored_credentials.push(StoredCredential {
        rp_id: rp_id.to_string(),
        user_id: vec![0x02],
        user_name: None,
        user_display_name: None,
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xBB],
        public_key: vec![0x04, 0x05, 0x06],
        secret_key: vec![0x20; 32],
        cred_random_with_uv: Some(vec![0x13; 32]),
        cred_random_without_uv: Some(vec![0x14; 32]),
        cred_protect: Some(1),
        sign_count: 0,
    });

    let request = canonical_map(vec![
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
    into_writer(&request, &mut payload).expect("serialize request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("assertion without UV succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode response") else {
        panic!("response must be a map");
    };
    let credential_id = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        .and_then(|(_, v)| match v {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| *k == Value::Text("id".into()))
                .and_then(|(_, v)| match v {
                    Value::Bytes(bytes) => Some(bytes.clone()),
                    _ => None,
                }),
            _ => None,
        })
        .expect("credential id present");
    assert_eq!(credential_id, vec![0xBB]);

    let pin_token = [0x66; 32];
    app.pin_state
        .set_pin_uv_auth_token(pin_token, PIN_PERMISSION_MC | PIN_PERMISSION_GA, None);
    let mut mac = HmacSha256::new_from_slice(&pin_token).expect("valid token");
    mac.update(&client_hash);
    let pin_uv_auth_param: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();

    let request_with_uv = canonical_map(vec![
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
    into_writer(&request_with_uv, &mut payload).expect("serialize request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("assertion with UV succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode response") else {
        panic!("response must be a map");
    };
    let credential_id = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        .and_then(|(_, v)| match v {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| *k == Value::Text("id".into()))
                .and_then(|(_, v)| match v {
                    Value::Bytes(bytes) => Some(bytes.clone()),
                    _ => None,
                }),
            _ => None,
        })
        .expect("credential id present");
    assert_eq!(credential_id, vec![0xAA]);
}

fn cm_pin_param(token: &[u8; 32], subcommand: u8, params: Option<Value>) -> Vec<u8> {
    let mut message = vec![subcommand];
    if let Some(value) = params {
        let mut encoded = Vec::new();
        into_writer(&value, &mut encoded).expect("encode params");
        message.extend_from_slice(&encoded);
    }
    let mut mac = HmacSha256::new_from_slice(token).expect("valid MAC key");
    mac.update(&message);
    mac.finalize().into_bytes()[..16].to_vec()
}

#[test]
fn credential_management_commands() {
    let mut app = CtapApp::new(TestClient::new(), [0x24; 16]);
    let token = [0x90; 32];
    app.pin_state
        .set_pin_uv_auth_token(token, PIN_PERMISSION_CM, None);

    app.stored_credentials.push(StoredCredential {
        rp_id: "example.com".into(),
        user_id: vec![0x01],
        user_name: Some("one".into()),
        user_display_name: None,
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xA1],
        public_key: vec![0x11, 0x22],
        secret_key: vec![0x33; 32],
        cred_random_with_uv: Some(vec![0x44; 32]),
        cred_random_without_uv: Some(vec![0x45; 32]),
        cred_protect: Some(1),
        sign_count: 0,
    });
    app.stored_credentials.push(StoredCredential {
        rp_id: "example.com".into(),
        user_id: vec![0x02],
        user_name: Some("two".into()),
        user_display_name: None,
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xA2],
        public_key: vec![0x12, 0x23],
        secret_key: vec![0x34; 32],
        cred_random_with_uv: Some(vec![0x46; 32]),
        cred_random_without_uv: Some(vec![0x47; 32]),
        cred_protect: Some(1),
        sign_count: 0,
    });
    app.stored_credentials.push(StoredCredential {
        rp_id: "second.example".into(),
        user_id: vec![0x03],
        user_name: Some("three".into()),
        user_display_name: Some("Three".into()),
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xB1],
        public_key: vec![0x21, 0x32],
        secret_key: vec![0x35; 32],
        cred_random_with_uv: Some(vec![0x48; 32]),
        cred_random_without_uv: Some(vec![0x49; 32]),
        cred_protect: Some(2),
        sign_count: 0,
    });

    let metadata_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x01)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x01, None)),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&metadata_request, &mut payload).expect("serialize metadata request");
    let response = app
        .handle_credential_management(&payload)
        .expect("metadata succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode metadata") else {
        panic!("metadata response must be map");
    };
    let existing: i128 = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone().into()),
            _ => None,
        })
        .expect("existing count");
    assert_eq!(existing, 3);

    let rp_hash = CtapApp::<TestClient>::cm_hash_rp_id("example.com");
    let rp_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x02)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x02, None)),
        ),
    ]);
    payload.clear();
    into_writer(&rp_request, &mut payload).expect("serialize RP begin");
    let response = app
        .handle_credential_management(&payload)
        .expect("rp begin succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode RP begin") else {
        panic!("response must be map");
    };
    assert!(map.iter().any(
        |(k, v)| *k == Value::Integer(Integer::from(4)) && *v == Value::Bytes(rp_hash.clone())
    ));

    let rp_next = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x03)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x03, None)),
        ),
    ]);
    payload.clear();
    into_writer(&rp_next, &mut payload).expect("serialize RP next");
    let response = app
        .handle_credential_management(&payload)
        .expect("rp next succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode RP next") else {
        panic!("response must be map");
    };
    assert!(map.iter().any(|(k, v)| {
        *k == Value::Integer(Integer::from(4))
            && *v == Value::Bytes(CtapApp::<TestClient>::cm_hash_rp_id("second.example"))
    }));

    let params = canonical_map(vec![(
        Value::Integer(Integer::from(1)),
        Value::Bytes(rp_hash.clone()),
    )]);
    let cred_begin = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x04)),
        ),
        (Value::Integer(Integer::from(2)), params.clone()),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x04, Some(params.clone()))),
        ),
    ]);
    payload.clear();
    into_writer(&cred_begin, &mut payload).expect("serialize credential begin");
    let response = app
        .handle_credential_management(&payload)
        .expect("credential begin succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode credential begin") else {
        panic!("response must be map");
    };
    let total: i128 = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(9)))
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone().into()),
            _ => None,
        })
        .expect("total credentials");
    assert_eq!(total, 2);

    let cred_next = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x05)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x05, None)),
        ),
    ]);
    payload.clear();
    into_writer(&cred_next, &mut payload).expect("serialize credential next");
    let response = app
        .handle_credential_management(&payload)
        .expect("credential next succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode credential next") else {
        panic!("response must be map");
    };
    assert!(map
        .iter()
        .any(|(k, v)| *k == Value::Integer(Integer::from(7)) && matches!(v, Value::Map(_))));

    let delete_descriptor = canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (Value::Text("id".into()), Value::Bytes(vec![0xA1])),
    ]);
    let delete_params = canonical_map(vec![(
        Value::Integer(Integer::from(2)),
        delete_descriptor.clone(),
    )]);
    let delete_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x06)),
        ),
        (Value::Integer(Integer::from(2)), delete_params.clone()),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x06, Some(delete_params))),
        ),
    ]);
    payload.clear();
    into_writer(&delete_request, &mut payload).expect("serialize delete");
    let response = app
        .handle_credential_management(&payload)
        .expect("delete succeeds");
    assert_eq!(response, vec![CTAP2_OK]);
    assert_eq!(app.stored_credentials.len(), 2);

    let update_descriptor = canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (Value::Text("id".into()), Value::Bytes(vec![0xA2])),
    ]);
    let updated_user = canonical_map(vec![
        (Value::Text("id".into()), Value::Bytes(vec![0x02])),
        (Value::Text("name".into()), Value::Text("updated".into())),
    ]);
    let update_params = canonical_map(vec![
        (Value::Integer(Integer::from(2)), update_descriptor.clone()),
        (Value::Integer(Integer::from(3)), updated_user.clone()),
    ]);
    let update_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x07)),
        ),
        (Value::Integer(Integer::from(2)), update_params.clone()),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x07, Some(update_params))),
        ),
    ]);
    payload.clear();
    into_writer(&update_request, &mut payload).expect("serialize update");
    let response = app
        .handle_credential_management(&payload)
        .expect("update succeeds");
    assert_eq!(response, vec![CTAP2_OK]);
    let updated = app
        .stored_credentials
        .iter()
        .find(|cred| cred.credential_id == vec![0xA2])
        .expect("credential remains");
    assert_eq!(updated.user_name.as_deref(), Some("updated"));
}

#[test]
fn credential_management_requires_cm_permission() {
    let mut app = CtapApp::new(TestClient::new(), [0x25; 16]);
    let token = [0x91; 32];
    app.pin_state
        .set_pin_uv_auth_token(token, PIN_PERMISSION_GA, None);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x01)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x01, None)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize metadata request");
    let result = app.handle_credential_management(&payload);
    assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID));
}

#[test]
fn credential_management_rejects_bound_token_for_rp_enumeration() {
    let mut app = CtapApp::new(TestClient::new(), [0x26; 16]);
    let token = [0x92; 32];
    app.pin_state
        .set_pin_uv_auth_token(token, PIN_PERMISSION_CM, Some("example.com".into()));

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x02)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x02, None)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize enumerate RPs request");
    let result = app.handle_credential_management(&payload);
    assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID));
}

#[test]
fn client_pin_get_retries_reports_available_attempts() {
    let mut app = CtapApp::new(TestClient::new(), [0x30; 16]);
    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x01)),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize getRetries request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getRetries succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode getRetries response") else {
        panic!("response must be a map");
    };
    let retries: i128 = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(0x03)))
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone().into()),
            _ => None,
        })
        .expect("retry count is present");
    assert_eq!(retries, i128::from(MAX_PIN_RETRIES));
    assert!(!map
        .iter()
        .any(|(k, _)| *k == Value::Integer(Integer::from(0x04))));
}

#[test]
fn client_pin_get_retries_includes_power_cycle_state_when_blocked() {
    let mut app = CtapApp::new(TestClient::new(), [0x31; 16]);
    let mut pin_hash = [0x11; 16];
    app.pin_state.set_pin(pin_hash);
    let wrong = [0x22; 16];
    for attempt in 0..MAX_PIN_FAILURES_BEFORE_BLOCK {
        let result = app.pin_state.verify_pin_hash(&wrong);
        if attempt + 1 < MAX_PIN_FAILURES_BEFORE_BLOCK {
            assert_eq!(result, Err(CTAP2_ERR_PIN_INVALID));
        } else {
            assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_BLOCKED));
        }
    }
    pin_hash.zeroize();

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x01)),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize getRetries request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getRetries succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode getRetries response") else {
        panic!("response must be a map");
    };
    let retries: i128 = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(0x03)))
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone().into()),
            _ => None,
        })
        .expect("retry count is present");
    let expected = MAX_PIN_RETRIES - MAX_PIN_FAILURES_BEFORE_BLOCK;
    assert_eq!(retries, i128::from(expected));
    let power_cycle = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(0x04)))
        .and_then(|(_, v)| match v {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        })
        .expect("power cycle flag present");
    assert!(power_cycle);
}

#[test]
fn pin_auth_blocked_persists_until_power_cycle() {
    let mut pin_state = PinState::new();
    let pin_hash = [0x33; 16];
    pin_state.set_pin(pin_hash);
    let wrong = [0x44; 16];

    for attempt in 0..MAX_PIN_FAILURES_BEFORE_BLOCK {
        let result = pin_state.verify_pin_hash(&wrong);
        if attempt + 1 < MAX_PIN_FAILURES_BEFORE_BLOCK {
            assert_eq!(result, Err(CTAP2_ERR_PIN_INVALID));
        } else {
            assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_BLOCKED));
        }
    }

    let retries_after_block = pin_state.retries();
    assert!(pin_state.needs_power_cycle());

    assert_eq!(
        pin_state.verify_pin_hash(&pin_hash),
        Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
    );
    assert_eq!(pin_state.retries(), retries_after_block);
    assert_eq!(
        pin_state.verify_pin_hash(&wrong),
        Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
    );
    assert_eq!(pin_state.retries(), retries_after_block);

    let mut restored_state = PinState::new();
    restored_state.set_pin(pin_hash);
    assert_eq!(restored_state.verify_pin_hash(&pin_hash), Ok(()));
    assert!(!restored_state.needs_power_cycle());
}

fn request_classic_key_agreement(
    app: &mut CtapApp<TestClient>,
    protocol: ClassicPinProtocol,
) -> Vec<(Value, Value)> {
    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(protocol.identifier())),
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
    protocol: ClassicPinProtocol,
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
    let keys = crate::derive_classic_pin_uv_session_keys(protocol, shared_bytes.as_ref());
    let platform_entries = classic_platform_key_entries(&platform_public);
    (keys, transcript_hash, platform_entries)
}

fn classic_encrypt(
    protocol: ClassicPinProtocol,
    keys: &PinUvSessionKeys,
    plaintext: &[u8],
    iv: Option<[u8; 16]>,
) -> Vec<u8> {
    match iv {
        Some(iv_bytes) => {
            crate::encrypt_classic_pin_block(protocol, keys, Some(&iv_bytes), plaintext)
                .expect("classic encryption succeeds")
        }
        None => crate::encrypt_classic_pin_block(protocol, keys, None, plaintext)
            .expect("classic encryption succeeds"),
    }
}

fn classic_pin_auth(protocol: ClassicPinProtocol, keys: &PinUvSessionKeys, data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(&keys.auth_key).expect("valid MAC key");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    match protocol {
        ClassicPinProtocol::V1 | ClassicPinProtocol::V2 => full[..16].to_vec(),
    }
}

fn run_classic_pin_flow(protocol: ClassicPinProtocol) {
    let mut app = CtapApp::new(TestClient::new(), [0xA5; 16]);
    let initial_pin = b"123456";
    let changed_pin = b"654321";

    // setPin
    let set_entries = request_classic_key_agreement(&mut app, protocol);
    let set_secret = P256SecretKey::from_slice(&[0x11; 32]).expect("valid secret key");
    let (set_keys, _set_hash, platform_entries) =
        derive_classic_session(protocol, &set_entries, &set_secret);
    let mut new_pin_block = [0u8; 64];
    new_pin_block[..initial_pin.len()].copy_from_slice(initial_pin);
    let set_iv = match protocol {
        ClassicPinProtocol::V1 => None,
        ClassicPinProtocol::V2 => Some([0x10; 16]),
    };
    let new_pin_enc = classic_encrypt(protocol, &set_keys, &new_pin_block, set_iv);
    new_pin_block.zeroize();
    let pin_auth = classic_pin_auth(protocol, &set_keys, &new_pin_enc);
    let set_pin_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(protocol.identifier())),
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
            Value::Bytes(pin_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(5)),
            Value::Bytes(new_pin_enc.clone()),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&set_pin_request, &mut payload).expect("serialize setPin request");
    let response = app.handle_client_pin(&payload).expect("setPin succeeds");
    assert_eq!(response, vec![CTAP2_OK]);
    assert!(app.pin_state.is_set());

    // changePin
    let change_entries = request_classic_key_agreement(&mut app, protocol);
    let change_secret = P256SecretKey::from_slice(&[0x22; 32]).expect("valid secret key");
    let (change_keys, _change_hash, change_platform_entries) =
        derive_classic_session(protocol, &change_entries, &change_secret);

    let mut hasher = Sha256::new();
    hasher.update(initial_pin);
    let current_hash_digest = hasher.finalize();
    let current_hash = &current_hash_digest[..16];
    let current_iv = match protocol {
        ClassicPinProtocol::V1 => None,
        ClassicPinProtocol::V2 => Some([0x11; 16]),
    };
    let pin_hash_enc = classic_encrypt(protocol, &change_keys, current_hash, current_iv);

    let mut next_pin_block = [0u8; 64];
    next_pin_block[..changed_pin.len()].copy_from_slice(changed_pin);
    let change_iv = match protocol {
        ClassicPinProtocol::V1 => None,
        ClassicPinProtocol::V2 => Some([0x12; 16]),
    };
    let new_pin_enc = classic_encrypt(protocol, &change_keys, &next_pin_block, change_iv);
    next_pin_block.zeroize();

    let mut auth_data = new_pin_enc.clone();
    auth_data.extend_from_slice(&pin_hash_enc);
    let change_pin_auth = classic_pin_auth(protocol, &change_keys, &auth_data);

    let change_pin_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(protocol.identifier())),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x04)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(change_platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(change_pin_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(5)),
            Value::Bytes(new_pin_enc.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
    ]);
    payload.clear();
    into_writer(&change_pin_request, &mut payload).expect("serialize changePin request");
    let response = app.handle_client_pin(&payload).expect("changePin succeeds");
    assert_eq!(response, vec![CTAP2_OK]);

    hasher = Sha256::new();
    hasher.update(changed_pin);
    let updated_digest = hasher.finalize();
    let mut expected_hash = [0u8; 16];
    expected_hash.copy_from_slice(&updated_digest[..16]);
    assert_eq!(app.pin_state.verify_pin_hash(&expected_hash), Ok(()));

    // getPinToken (legacy)
    let token_entries = request_classic_key_agreement(&mut app, protocol);
    let token_secret = P256SecretKey::from_slice(&[0x33; 32]).expect("valid secret key");
    let (token_keys, _token_hash, token_platform_entries) =
        derive_classic_session(protocol, &token_entries, &token_secret);

    let token_iv = match protocol {
        ClassicPinProtocol::V1 => None,
        ClassicPinProtocol::V2 => Some([0x13; 16]),
    };
    let pin_hash_enc = classic_encrypt(protocol, &token_keys, &expected_hash, token_iv);
    let pin_hash_auth = classic_pin_auth(protocol, &token_keys, &pin_hash_enc);

    let get_token_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(protocol.identifier())),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x05)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(token_platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(pin_hash_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
    ]);
    payload.clear();
    into_writer(&get_token_request, &mut payload).expect("serialize getPinToken request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getPinToken succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode getPinToken response") else {
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
    let decrypted_token = crate::decrypt_classic_pin_block(protocol, &token_keys, &encrypted_token)
        .expect("token decrypts");
    assert_eq!(decrypted_token.len(), 32);
    let mut expected_token = [0u8; 32];
    expected_token.copy_from_slice(&decrypted_token);
    assert_eq!(app.pin_state.pin_uv_auth_token(), Some(expected_token));
}

#[test]
fn client_pin_token_with_permissions_sets_metadata() {
    let mut app = CtapApp::new(TestClient::new(), [0xA7; 16]);
    let pin = b"1234";
    let mut hasher = Sha256::new();
    hasher.update(pin);
    let digest = hasher.finalize();
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&digest[..16]);
    app.pin_state.set_pin(pin_hash);

    let auth_entries = request_classic_key_agreement(&mut app, ClassicPinProtocol::V2);
    let platform_secret = P256SecretKey::from_slice(&[0x33; 32]).expect("valid platform secret");
    let (keys, _transcript_hash, platform_entries) =
        derive_classic_session(ClassicPinProtocol::V2, &auth_entries, &platform_secret);
    let iv = [0xAA; 16];
    let pin_hash_enc = classic_encrypt(ClassicPinProtocol::V2, &keys, &digest[..16], Some(iv));
    let pin_auth = classic_pin_auth(ClassicPinProtocol::V2, &keys, &pin_hash_enc);

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x09)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(pin_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(
                (PIN_PERMISSION_MC | PIN_PERMISSION_GA) as i32,
            )),
        ),
        (
            Value::Integer(Integer::from(10)),
            Value::Text("example.com".into()),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize permissions request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getPinUvAuthTokenWithPermissions succeeds");
    assert_eq!(response[0], CTAP2_OK);
    assert!(app.pin_state.has_permission(PIN_PERMISSION_MC));
    assert!(app.pin_state.has_permission(PIN_PERMISSION_GA));
    assert!(!app.pin_state.has_permission(PIN_PERMISSION_CM));
    assert_eq!(app.pin_state.permissions_rp_id(), Some("example.com"));
}

#[test]
fn client_pin_get_token_legacy_succeeds_without_pin_uv_auth_param() {
    let mut app = CtapApp::new(TestClient::new(), [0xAA; 16]);
    let pin = b"9876";
    let mut hasher = Sha256::new();
    hasher.update(pin);
    let digest = hasher.finalize();
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&digest[..16]);
    app.pin_state.set_pin(pin_hash);

    let auth_entries = request_classic_key_agreement(&mut app, ClassicPinProtocol::V2);
    let platform_secret = P256SecretKey::from_slice(&[0x55; 32]).expect("valid platform secret");
    let (keys, _transcript_hash, platform_entries) =
        derive_classic_session(ClassicPinProtocol::V2, &auth_entries, &platform_secret);
    let iv = [0xCC; 16];
    let pin_hash_enc = classic_encrypt(ClassicPinProtocol::V2, &keys, &digest[..16], Some(iv));

    let request_map = canonical_map(vec![
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
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize getPinToken request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getPinToken without pinUvAuthParam succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) =
        from_reader(&response[1..]).expect("decode getPinToken response without pinUvAuthParam")
    else {
        panic!("response must be a map");
    };
    let encrypted_token = map
        .into_iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        })
        .expect("encrypted token present");
    let decrypted_token =
        crate::decrypt_classic_pin_block(ClassicPinProtocol::V2, &keys, &encrypted_token)
            .expect("token decrypts");
    assert_eq!(decrypted_token.len(), 32);
    let mut expected_token = [0u8; 32];
    expected_token.copy_from_slice(&decrypted_token);
    assert_eq!(app.pin_state.pin_uv_auth_token(), Some(expected_token));
}

#[test]
fn client_pin_token_with_permissions_accepts_missing_pin_uv_auth_param() {
    let mut app = CtapApp::new(TestClient::new(), [0xAB; 16]);
    let pin = b"2468";
    let mut hasher = Sha256::new();
    hasher.update(pin);
    let digest = hasher.finalize();
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&digest[..16]);
    app.pin_state.set_pin(pin_hash);

    let auth_entries = request_classic_key_agreement(&mut app, ClassicPinProtocol::V2);
    let platform_secret = P256SecretKey::from_slice(&[0x66; 32]).expect("valid platform secret");
    let (keys, _transcript_hash, platform_entries) =
        derive_classic_session(ClassicPinProtocol::V2, &auth_entries, &platform_secret);
    let iv = [0xDD; 16];
    let pin_hash_enc = classic_encrypt(ClassicPinProtocol::V2, &keys, &digest[..16], Some(iv));

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x09)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(
                (PIN_PERMISSION_MC | PIN_PERMISSION_GA) as i32,
            )),
        ),
        (
            Value::Integer(Integer::from(10)),
            Value::Text("example.org".into()),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload)
        .expect("serialize getPinUvAuthTokenWithPermissions request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getPinUvAuthTokenWithPermissions without pinUvAuthParam succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) =
        from_reader(&response[1..]).expect("decode getPinUvAuthTokenWithPermissions response")
    else {
        panic!("response must be a map");
    };
    let encrypted_token = map
        .into_iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        })
        .expect("encrypted token present");
    let decrypted_token =
        crate::decrypt_classic_pin_block(ClassicPinProtocol::V2, &keys, &encrypted_token)
            .expect("token decrypts");
    assert_eq!(decrypted_token.len(), 32);
    let mut expected_token = [0u8; 32];
    expected_token.copy_from_slice(&decrypted_token);
    assert_eq!(app.pin_state.pin_uv_auth_token(), Some(expected_token));
    assert!(app.pin_state.has_permission(PIN_PERMISSION_MC));
    assert!(app.pin_state.has_permission(PIN_PERMISSION_GA));
    assert!(!app.pin_state.has_permission(PIN_PERMISSION_CM));
    assert_eq!(app.pin_state.permissions_rp_id(), Some("example.org"));
}

#[test]
fn client_pin_token_with_permissions_requires_rp_id() {
    let mut app = CtapApp::new(TestClient::new(), [0xA8; 16]);
    let pin = b"1234";
    let mut hasher = Sha256::new();
    hasher.update(pin);
    let digest = hasher.finalize();
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&digest[..16]);
    app.pin_state.set_pin(pin_hash);

    let auth_entries = request_classic_key_agreement(&mut app, ClassicPinProtocol::V2);
    let platform_secret = P256SecretKey::from_slice(&[0x44; 32]).expect("valid platform secret");
    let (keys, _transcript_hash, platform_entries) =
        derive_classic_session(ClassicPinProtocol::V2, &auth_entries, &platform_secret);
    let iv = [0xBB; 16];
    let pin_hash_enc = classic_encrypt(ClassicPinProtocol::V2, &keys, &digest[..16], Some(iv));
    let pin_auth = classic_pin_auth(ClassicPinProtocol::V2, &keys, &pin_hash_enc);

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x09)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(pin_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(
                (PIN_PERMISSION_MC | PIN_PERMISSION_GA) as i32,
            )),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize permissions request");
    let result = app.handle_client_pin(&payload);
    assert_eq!(result, Err(CTAP2_ERR_MISSING_PARAMETER));
}

#[test]
fn classic_pin_uv_protocol_flow_v1() {
    run_classic_pin_flow(ClassicPinProtocol::V1);
}

#[test]
fn classic_pin_uv_protocol_flow_v2() {
    run_classic_pin_flow(ClassicPinProtocol::V2);
}
