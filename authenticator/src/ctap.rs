use crate::{create_credential, sign_challenge, CoseAlg, PIN_UV_AUTH_PROTOCOL_PQC};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use ctaphid_app::{App, Command, Error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trussed::{
    client::{Client as TrussedClient, CryptoClient, FilesystemClient},
    syscall, try_syscall,
    types::{Location, Message, PathBuf},
};

use trussed_mldsa::SecretKey;

const CTAP_CMD_MAKE_CREDENTIAL: u8 = 0x01;
const CTAP_CMD_GET_ASSERTION: u8 = 0x02;
const CTAP_CMD_GET_INFO: u8 = 0x04;

const CTAP2_OK: u8 = 0x00;
const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const CTAP2_ERR_INVALID_OPTION: u8 = 0x2C;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
const CTAP2_ERR_PROCESSING: u8 = 0x21;

const CREDENTIAL_STORE_PATH: &str = "credentials.cbor";

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

pub struct CtapApp<C> {
    client: C,
    aaguid: [u8; 16],
}

impl<C> CtapApp<C> {
    pub fn new(client: C, aaguid: [u8; 16]) -> Self {
        Self { client, aaguid }
    }
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    fn store_path() -> Result<PathBuf, u8> {
        PathBuf::try_from(CREDENTIAL_STORE_PATH).map_err(|_| CTAP2_ERR_PROCESSING)
    }

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

    fn map_get<'a>(map: &'a [(Value, Value)], key: Value) -> Option<&'a Value> {
        map.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    fn attested_auth_data(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        cose_key: &[u8],
        uv: bool,
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
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&self.aaguid);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(cose_key);
        auth_data
    }

    fn assertion_auth_data(&self, rp_id: &str, sign_count: u32, uv: bool) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let rp_hash = hasher.finalize();

        let mut auth_data = Vec::with_capacity(32 + 1 + 4);
        auth_data.extend_from_slice(&rp_hash);
        let mut flags = 0x01; // UP
        if uv {
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

        let options = Value::Map(vec![
            (Value::Text("rk".into()), Value::Bool(true)),
            (Value::Text("uv".into()), Value::Bool(true)),
            (Value::Text("up".into()), Value::Bool(true)),
            (Value::Text("pinUvAuthToken".into()), Value::Bool(true)),
        ]);
        map.push((Value::Integer(Integer::from(4)), options));

        map.push((
            Value::Integer(Integer::from(5)),
            Value::Integer(Integer::from(2048)),
        ));

        map.push((
            Value::Integer(Integer::from(6)),
            Value::Array(vec![Value::Integer(Integer::from(i32::from(
                PIN_UV_AUTH_PROTOCOL_PQC,
            )))]),
        ));

        map.push((
            Value::Integer(Integer::from(8)),
            Value::Integer(Integer::from(128)),
        ));

        let algorithms = [-48, -49, -50]
            .into_iter()
            .map(|alg| {
                Value::Map(vec![
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

        let _client_hash = match Self::map_get(&map, Value::Integer(Integer::from(1))) {
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

        if let Some(protocol) = Self::map_get(&map, Value::Integer(Integer::from(9))) {
            let Value::Integer(int) = protocol else {
                return Err(CTAP2_ERR_INVALID_CBOR);
            };
            let value: i128 = int.clone().into();
            if value as i32 != PIN_UV_AUTH_PROTOCOL_PQC.into() {
                return Err(CTAP2_ERR_PIN_AUTH_INVALID);
            }
        }

        let (cose_key, secret_key) = create_credential(alg);
        let credential_id_bytes = syscall!(self.client.random_bytes(32)).bytes;
        let credential_id = credential_id_bytes.to_vec();

        let mut credentials = self.load_credentials()?;
        credentials.push(StoredCredential {
            rp_id: rp_id.clone(),
            user_id: user_id.clone(),
            user_name,
            user_display_name,
            alg: alg as i32,
            credential_id: credential_id.clone(),
            public_key: cose_key.clone(),
            secret_key: secret_key.0.clone(),
            sign_count: 0,
        });
        self.save_credentials(&credentials)?;

        let uv = uv_requested;
        let auth_data = self.attested_auth_data(&rp_id, &credential_id, &cose_key, uv);

        let response_map = vec![
            (Value::Integer(Integer::from(1)), Value::Text("none".into())),
            (
                Value::Integer(Integer::from(2)),
                Value::Bytes(auth_data.clone()),
            ),
            (Value::Integer(Integer::from(3)), Value::Map(Vec::new())),
        ];

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

        if let Some(Value::Map(options)) = Self::map_get(&map, Value::Integer(Integer::from(5))) {
            if let Some(Value::Bool(false)) = Self::map_get(options, Value::Text("up".into())) {
                return Err(CTAP2_ERR_INVALID_OPTION);
            }
            if let Some(Value::Bool(false)) = Self::map_get(options, Value::Text("uv".into())) {
                return Err(CTAP2_ERR_INVALID_OPTION);
            }
        }

        let pin_protocol = match Self::map_get(&map, Value::Integer(Integer::from(7))) {
            Some(Value::Integer(int)) => {
                let value: i128 = int.clone().into();
                value as i32
            }
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        if pin_protocol != PIN_UV_AUTH_PROTOCOL_PQC.into() {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }

        match Self::map_get(&map, Value::Integer(Integer::from(6))) {
            Some(Value::Bytes(bytes)) if bytes.len() == 32 => bytes.clone(),
            _ => return Err(CTAP2_ERR_PIN_AUTH_INVALID),
        };

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
        let auth_data = self.assertion_auth_data(&rp_id, sign_count, true);
        let signature = sign_challenge(alg, &signing_key, &auth_data, &client_hash);
        self.save_credentials(&credentials)?;

        let credential_map = Value::Map(vec![
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
        let user_map = Value::Map(user_entries);

        let response = vec![
            (Value::Integer(Integer::from(1)), credential_map),
            (Value::Integer(Integer::from(2)), Value::Bytes(auth_data)),
            (Value::Integer(Integer::from(3)), Value::Bytes(signature)),
            (Value::Integer(Integer::from(4)), user_map),
        ];

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
