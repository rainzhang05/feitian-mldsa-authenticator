pub mod permissions;
pub mod service;
pub mod transport;
pub mod uhid;

use std::{
    io,
    time::{Duration, Instant},
};

use ctaphid_dispatch::{self, Channel, DEFAULT_MESSAGE_SIZE};
use transport::ctaphid_host::{CtaphidHost, Version};
pub use transport_core::{
    set_waiting, waiting_for_user_presence, Apps, Builder, Client, Options, Platform, Runner,
    Store, Syscall, Timeout, Transport,
};
use trussed::backend::Dispatch;
pub use uhid::{CtapHidFrame, HidDeviceDescriptor, ReportType, UhidDevice, CTAPHID_FRAME_LEN};

pub struct UhidTransport<'pipe, 'interrupt> {
    device: UhidDevice,
    host: CtaphidHost<'pipe, { DEFAULT_MESSAGE_SIZE }>,
    dispatch: ctaphid_dispatch::Dispatch<'pipe, 'interrupt, { DEFAULT_MESSAGE_SIZE }>,
    epoch: Instant,
}

impl<'pipe, 'interrupt> UhidTransport<'pipe, 'interrupt> {
    pub fn new(
        device: UhidDevice,
        host: CtaphidHost<'pipe, { DEFAULT_MESSAGE_SIZE }>,
        dispatch: ctaphid_dispatch::Dispatch<'pipe, 'interrupt, { DEFAULT_MESSAGE_SIZE }>,
    ) -> Self {
        Self {
            device,
            host,
            dispatch,
            epoch: Instant::now(),
        }
    }

    fn flush_pending(&mut self) -> io::Result<bool> {
        let mut wrote = false;
        while let Some(frame) = self.host.next_outgoing_frame() {
            self.device.write_frame(&frame)?;
            wrote = true;
        }
        Ok(wrote)
    }
}

impl<'interrupt, D> Transport<'interrupt, D> for UhidTransport<'_, 'interrupt>
where
    D: Dispatch,
{
    fn poll<A: Apps<'interrupt, D>>(&mut self, apps: &mut A) -> io::Result<bool> {
        let mut did_work = false;
        loop {
            match self.device.try_read_frame()? {
                Some(frame) => {
                    let elapsed = self.epoch.elapsed().as_millis() as u64;
                    self.host.handle_frame(&frame, elapsed);
                    did_work = true;
                }
                None => break,
            }
        }

        did_work |=
            apps.with_ctaphid_apps(|apps| self.host.poll_dispatch(&mut self.dispatch, apps));

        if self.host.take_started_processing() {
            did_work = true;
        }

        if self.host.has_pending_frames() {
            did_work |= self.flush_pending()?;
        }

        Ok(did_work)
    }

    fn send(&mut self, waiting_for_user: bool) -> io::Result<bool> {
        let elapsed = self.epoch.elapsed().as_millis() as u64;
        self.host.handle_timeout(elapsed);
        let mut did_work = false;
        if self.host.send_keepalive(waiting_for_user) {
            did_work |= self.flush_pending()?;
        }
        if self.host.has_pending_frames() {
            did_work |= self.flush_pending()?;
        }
        Ok(did_work)
    }

    fn wait(&mut self) -> io::Result<()> {
        let _ = self.device.wait(Some(Duration::from_millis(10)))?;
        Ok(())
    }
}

pub fn exec<'interrupt, D, A>(
    runner: Runner<D, A>,
    descriptor: HidDeviceDescriptor,
    platform: Platform,
    data: A::Data,
) -> io::Result<()>
where
    D: Dispatch,
    D::BackendId: Send + Sync,
    D::Context: Send + Sync,
    A: Apps<'interrupt, D>,
{
    let descriptor_clone = descriptor.clone();
    let device = UhidDevice::new(descriptor)?;
    if let Ok(nodes) = permissions::hidraw_nodes_for_descriptor(&descriptor_clone) {
        for node in nodes {
            let mode = node.mode & 0o777;
            if mode & 0o007 != 0 {
                log::warn!(
                    "{} is world-accessible (mode {:o}); install the bundled udev rule or tighten permissions",
                    node.path.display(),
                    mode
                );
            }
        }
    }
    let channel: Channel<{ DEFAULT_MESSAGE_SIZE }> = Channel::new();
    let (requester, responder) = channel
        .split()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to split CTAPHID channel"))?;
    let mut host = CtaphidHost::new(requester);
    host.set_version(Version {
        major: 2,
        minor: 1,
        build: 0,
    });
    host.set_capabilities(0x05);
    let dispatch = ctaphid_dispatch::Dispatch::new(responder);
    let transport = UhidTransport::new(device, host, dispatch);
    runner.exec(platform, data, transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticator::{
        ctap::{CtapApp, PqcPolicy},
        COSE_ALG_ML_KEM_512, COSE_KEY_LABEL_ALG,
    };
    use ciborium::{
        de::from_reader,
        value::{Integer, Value},
    };
    use ctaphid_dispatch::{app::App, Channel, DEFAULT_MESSAGE_SIZE};
    use std::collections::{HashMap, VecDeque};
    use trussed::api::{reply, Reply, Request, RequestVariant};
    use trussed::client::{
        AttestationClient, CertificateClient, Client as TrussedClient, ClientResult, CounterClient,
        CryptoClient, FilesystemClient, FutureResult, ManagementClient, PollClient, UiClient,
    };
    use trussed::error::Error as TrussedError;
    use trussed::types::{consent, Message};

    const CTAP_CMD_CLIENT_PIN: u8 = 0x06;
    const CTAP2_OK: u8 = 0x00;
    const ALG_ES256: i32 = -25;

    #[derive(Default)]
    struct TestClient {
        pending: Option<Result<Reply, TrussedError>>,
        random_counter: u8,
        files: HashMap<Vec<u8>, Vec<u8>>,
        presence_responses: VecDeque<consent::Result>,
    }

    impl TestClient {
        fn new() -> Self {
            Self::default()
        }
    }

    impl PollClient for TestClient {
        fn request<Rq: RequestVariant>(&mut self, req: Rq) -> ClientResult<'_, Rq::Reply, Self> {
            assert!(self.pending.is_none(), "a request is already pending");
            let request: Request = req.into();
            self.pending = Some(match request {
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
                Request::RequestUserConsent(_) => {
                    let result =
                        self.presence_responses
                            .pop_front()
                            .unwrap_or(Ok::<(), consent::Error>(()));
                    Ok(Reply::from(reply::RequestUserConsent { result }))
                }
                _ => Err(TrussedError::FunctionNotSupported),
            });
            Ok(FutureResult::new(self))
        }

        fn poll(&mut self) -> core::task::Poll<Result<Reply, TrussedError>> {
            match self.pending.take() {
                Some(result) => core::task::Poll::Ready(result),
                None => core::task::Poll::Pending,
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

    fn init_harness() -> (
        CtaphidHost<'static, DEFAULT_MESSAGE_SIZE>,
        ctaphid_dispatch::Dispatch<'static, 'static, DEFAULT_MESSAGE_SIZE>,
        CtapApp<TestClient>,
    ) {
        let channel = Box::leak(Box::new(Channel::<{ DEFAULT_MESSAGE_SIZE }>::new()));
        let (requester, responder) = channel.split().expect("ctaphid channel split");
        let mut host = CtaphidHost::new(requester);
        host.set_version(Version {
            major: 2,
            minor: 1,
            build: 0,
        });
        host.set_capabilities(0x05);
        let dispatch = ctaphid_dispatch::Dispatch::new(responder);
        let mut app = CtapApp::new(TestClient::new(), [0xAB; 16]);
        app.set_auto_user_presence(true);
        app.set_pqc_policy(PqcPolicy::PreferPqc);
        app.set_keepalive_callback(|_| {});
        (host, dispatch, app)
    }

    fn take_frames(host: &mut CtaphidHost<'static, DEFAULT_MESSAGE_SIZE>) -> Vec<[u8; 64]> {
        let mut frames = Vec::new();
        while let Some(frame) = host.next_outgoing_frame() {
            frames.push(*frame.as_bytes());
        }
        frames
    }

    fn drive_dispatch(
        host: &mut CtaphidHost<'static, DEFAULT_MESSAGE_SIZE>,
        dispatch: &mut ctaphid_dispatch::Dispatch<'static, 'static, DEFAULT_MESSAGE_SIZE>,
        app: &mut CtapApp<TestClient>,
    ) {
        let mut apps: [&mut dyn App<'static, DEFAULT_MESSAGE_SIZE>; 1] = [app];
        host.poll_dispatch(dispatch, &mut apps);
    }

    fn perform_init(
        host: &mut CtaphidHost<'static, DEFAULT_MESSAGE_SIZE>,
        dispatch: &mut ctaphid_dispatch::Dispatch<'static, 'static, DEFAULT_MESSAGE_SIZE>,
        app: &mut CtapApp<TestClient>,
    ) -> u32 {
        let mut init_packet = [0u8; 64];
        init_packet[..4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        init_packet[4] = ctaphid_dispatch::app::Command::Init.into_u8() | 0x80;
        init_packet[5..7].copy_from_slice(&(8u16).to_be_bytes());
        init_packet[7..15].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        host.handle_frame(&CtapHidFrame::new(init_packet), 0);
        drive_dispatch(host, dispatch, app);
        let frames = take_frames(host);
        assert_eq!(frames.len(), 1);
        let response = &frames[0];
        assert_eq!(
            response[4] & 0x7F,
            ctaphid_dispatch::app::Command::Init.into_u8()
        );
        let mut channel_bytes = [0u8; 4];
        channel_bytes.copy_from_slice(&response[7..11]);
        u32::from_be_bytes(channel_bytes)
    }

    fn send_client_pin_get_key_agreement(
        host: &mut CtaphidHost<'static, DEFAULT_MESSAGE_SIZE>,
        dispatch: &mut ctaphid_dispatch::Dispatch<'static, 'static, DEFAULT_MESSAGE_SIZE>,
        app: &mut CtapApp<TestClient>,
        channel: u32,
        protocol: Option<i32>,
    ) -> Value {
        use ciborium::ser::into_writer;

        let mut map_entries = vec![(
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x02)),
        )];
        if let Some(protocol) = protocol {
            map_entries.push((
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(protocol)),
            ));
        }
        map_entries.sort_by(|(ka, _), (kb, _)| {
            fn integer_key(value: &Value) -> i128 {
                if let Value::Integer(int) = value {
                    let number: i128 = int.clone().into();
                    number
                } else {
                    panic!("map key must be integer");
                }
            }
            integer_key(ka).cmp(&integer_key(kb))
        });
        let payload_map = Value::Map(map_entries);
        let mut encoded = Vec::new();
        into_writer(&payload_map, &mut encoded).expect("encode CBOR map");

        let mut packet = [0u8; 64];
        packet[..4].copy_from_slice(&channel.to_be_bytes());
        packet[4] = ctaphid_dispatch::app::Command::Cbor.into_u8() | 0x80;
        let total_len = 1 + encoded.len();
        packet[5..7].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[7] = CTAP_CMD_CLIENT_PIN;
        packet[8..8 + encoded.len()].copy_from_slice(&encoded);
        host.handle_frame(&CtapHidFrame::new(packet), 1);
        drive_dispatch(host, dispatch, app);
        let frames = take_frames(host);
        assert_eq!(frames.len(), 1, "expected single response frame");
        let frame = &frames[0];
        assert_eq!(
            frame[4] & 0x7F,
            ctaphid_dispatch::app::Command::Cbor.into_u8()
        );
        let len = u16::from_be_bytes([frame[5], frame[6]]) as usize;
        let mut body = vec![0u8; len];
        body.copy_from_slice(&frame[7..7 + len]);
        assert_eq!(body[0], CTAP2_OK);
        from_reader(&body[1..]).expect("decode CBOR response")
    }

    fn extract_alg(value: &Value) -> i32 {
        let Value::Map(entries) = value else {
            panic!("response must be a map");
        };
        let key_map = entries
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(int) = k {
                    let key: i128 = int.clone().into();
                    if key == 1 {
                        Some(v)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .expect("response must include keyAgreement map");
        let Value::Map(kv) = key_map else {
            panic!("keyAgreement must be map");
        };
        let alg_value = kv
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(int) = k {
                    let key: i128 = int.clone().into();
                    if key == i128::from(COSE_KEY_LABEL_ALG) {
                        Some(v)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .expect("keyAgreement must include alg");
        match alg_value {
            Value::Integer(int) => {
                let value: i128 = int.clone().into();
                value as i32
            }
            _ => panic!("alg must be integer"),
        }
    }

    #[test]
    fn falls_back_to_classic_pin_protocol_when_platform_declines_pqc() {
        let (mut host, mut dispatch, mut app) = init_harness();
        let channel = perform_init(&mut host, &mut dispatch, &mut app);

        let response =
            send_client_pin_get_key_agreement(&mut host, &mut dispatch, &mut app, channel, None);
        let alg = extract_alg(&response);
        assert_eq!(alg, i32::from(COSE_ALG_ML_KEM_512));

        let response =
            send_client_pin_get_key_agreement(&mut host, &mut dispatch, &mut app, channel, Some(2));
        let alg = extract_alg(&response);
        assert_eq!(alg, ALG_ES256, "classic PIN request should use ES256");

        let response =
            send_client_pin_get_key_agreement(&mut host, &mut dispatch, &mut app, channel, None);
        let alg = extract_alg(&response);
        assert_eq!(
            alg, ALG_ES256,
            "platform decline should trigger classic fallback"
        );
    }
}
