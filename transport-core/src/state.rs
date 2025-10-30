use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    Key, XChaCha20, XNonce,
};
use ciborium::ser::into_writer;
use littlefs2::path;
use littlefs2::{consts, driver::Storage, fs::Filesystem, io::Error as LittleFsError};
use littlefs2_core::DynFilesystem;
use p256::{pkcs8::EncodePrivateKey, SecretKey};
use rand_core::{OsRng, RngCore};
use rcgen::{
    Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType, SerialNumber,
    PKCS_ECDSA_P256_SHA256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::Store;

const READ_SIZE: usize = 32;
const WRITE_SIZE: usize = 32;
const BLOCK_SIZE: usize = 256;
const BLOCK_COUNT: usize = 512;
const FILE_LENGTH: u64 = (BLOCK_SIZE * BLOCK_COUNT) as u64;

fn map_fs_error(err: LittleFsError) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("littlefs error {}", err.code()),
    )
}

fn lfs_io_error() -> LittleFsError {
    LittleFsError::IO
}

fn write_exact_at(file: &File, mut offset: u64, mut data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;

    while !data.is_empty() {
        let written = file.write_at(data, offset)?;
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
        }
        offset += written as u64;
        data = &data[written..];
    }
    Ok(())
}

fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;

    file.read_exact_at(buf, offset)
}

fn ensure_permissions(path: &Path, mode: u32) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)
}

fn load_or_generate_seed(dir: &Path) -> io::Result<[u8; 32]> {
    let seed_path = dir.join("master.seed");
    if seed_path.exists() {
        let mut file = File::open(&seed_path)?;
        let mut seed = [0u8; 32];
        file.read_exact(&mut seed)?;
        Ok(seed)
    } else {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        options.mode(0o600);
        let mut file = options.open(&seed_path)?;
        file.write_all(&seed)?;
        file.sync_data()?;
        Ok(seed)
    }
}

fn derive_material(seed: &[u8; 32], label: &str) -> ([u8; 32], [u8; 24]) {
    let mut hasher = Sha512::new();
    hasher.update(seed);
    hasher.update(label.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&digest[32..56]);
    (key, nonce)
}

struct FilesystemBundle {
    fs: &'static dyn DynFilesystem,
    freshly_formatted: bool,
}

fn mount_filesystem(base: &Path, label: &str, seed: &[u8; 32]) -> io::Result<FilesystemBundle> {
    let (key, nonce) = derive_material(seed, label);
    let path = base.join(format!("{label}.lfs2"));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    options.mode(0o600);
    let file = options.open(&path)?;
    file.set_len(FILE_LENGTH)?;
    ensure_permissions(&path, 0o600)?;
    let storage = Box::leak(Box::new(EncryptedFileStorage::new(file, key, nonce)));
    let alloc = Box::leak(Box::new(Filesystem::allocate()));
    let storage_ptr: *mut EncryptedFileStorage = storage;
    let alloc_ptr: *mut littlefs2::fs::Allocation<EncryptedFileStorage> = alloc;
    let mut freshly_formatted = false;
    let mut mounted = unsafe { Filesystem::mount(&mut *alloc_ptr, &mut *storage_ptr) };
    if let Err(err) = mounted {
        log::warn!("Formatting littlefs image {label}: {err:?}");
        unsafe {
            Filesystem::format(&mut *storage_ptr).map_err(map_fs_error)?;
        }
        freshly_formatted = true;
        mounted = unsafe { Filesystem::mount(&mut *alloc_ptr, &mut *storage_ptr) };
    }
    let fs = mounted.map_err(map_fs_error)?;
    let fs = Box::leak(Box::new(fs));
    let dyn_fs: &'static dyn DynFilesystem = &*fs;
    Ok(FilesystemBundle {
        fs: dyn_fs,
        freshly_formatted,
    })
}

pub fn default_state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir).join("feitian-mldsa-authenticator")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share/feitian-mldsa-authenticator")
    } else {
        PathBuf::from("./feitian-mldsa-authenticator")
    }
}

pub fn ensure_state_dir(path: &Path) -> io::Result<()> {
    if path.exists() {
        if !path.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "state path exists but is not a directory",
            ));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    ensure_permissions(path, 0o700)
}

pub struct PersistentStore {
    ifs: &'static dyn DynFilesystem,
    efs: &'static dyn DynFilesystem,
    vfs: &'static dyn DynFilesystem,
    internal_fresh: bool,
    external_fresh: bool,
    volatile_fresh: bool,
}

impl PersistentStore {
    pub fn new(base: &Path) -> io::Result<Self> {
        ensure_state_dir(base)?;
        let seed = load_or_generate_seed(base)?;
        let internal = mount_filesystem(base, "internal", &seed)?;
        let external = mount_filesystem(base, "external", &seed)?;
        let volatile = mount_filesystem(base, "volatile", &seed)?;
        Ok(Self {
            ifs: internal.fs,
            efs: external.fs,
            vfs: volatile.fs,
            internal_fresh: internal.freshly_formatted,
            external_fresh: external.freshly_formatted,
            volatile_fresh: volatile.freshly_formatted,
        })
    }

    pub fn store(&self) -> Store {
        Store {
            ifs: self.ifs,
            efs: self.efs,
            vfs: self.vfs,
        }
    }

    pub fn internal_fresh(&self) -> bool {
        self.internal_fresh
    }

    pub fn external_fresh(&self) -> bool {
        self.external_fresh
    }

    pub fn volatile_fresh(&self) -> bool {
        self.volatile_fresh
    }

    pub fn initialize_identity(&mut self, identity: IdentityConfig<'_>) -> io::Result<()> {
        let fs = self.store().ifs;
        ensure_attestation(fs, &identity)?;
        ensure_pin_state(fs)?;
        ensure_metadata(fs, &identity)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct IdentityConfig<'a> {
    pub aaguid: [u8; 16],
    pub manufacturer: &'a str,
    pub product: &'a str,
    pub serial: &'a str,
}

#[derive(Serialize, Deserialize)]
struct StoredAttestation {
    private_key: Vec<u8>,
    certificate_chain: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct StoredPinState {
    pin_hash: Option<[u8; 16]>,
    pin_retries: u8,
    consecutive_failures: u8,
    pin_auth_blocked: bool,
}

#[derive(Serialize, Deserialize)]
struct StoredDeviceMetadata {
    aaguid: [u8; 16],
    manufacturer: String,
    product: String,
    serial: String,
}

pub struct EncryptedFileStorage {
    file: File,
    key: [u8; 32],
    nonce: [u8; 24],
}

fn ensure_attestation(
    fs: &'static dyn DynFilesystem,
    identity: &IdentityConfig<'_>,
) -> io::Result<()> {
    if fs.exists(&path!("attestation.cbor")) {
        return Ok(());
    }

    let (private_key, certificate) = generate_attestation_certificate(identity)?;
    let attestation = StoredAttestation {
        private_key,
        certificate_chain: vec![certificate],
    };
    let mut encoded = Vec::new();
    into_writer(&attestation, &mut encoded)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to encode attestation"))?;
    fs.write(&path!("attestation.cbor"), &encoded)
        .map_err(map_fs_error)
}

fn ensure_pin_state(fs: &'static dyn DynFilesystem) -> io::Result<()> {
    if fs.exists(&path!("pin-state.cbor")) {
        return Ok(());
    }
    let pin_state = StoredPinState {
        pin_hash: None,
        pin_retries: 8,
        consecutive_failures: 0,
        pin_auth_blocked: false,
    };
    let mut encoded = Vec::new();
    into_writer(&pin_state, &mut encoded)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to encode pin state"))?;
    fs.write(&path!("pin-state.cbor"), &encoded)
        .map_err(map_fs_error)
}

fn ensure_metadata(
    fs: &'static dyn DynFilesystem,
    identity: &IdentityConfig<'_>,
) -> io::Result<()> {
    if fs.exists(&path!("device-info.cbor")) {
        return Ok(());
    }
    let metadata = StoredDeviceMetadata {
        aaguid: identity.aaguid,
        manufacturer: identity.manufacturer.to_string(),
        product: identity.product.to_string(),
        serial: identity.serial.to_string(),
    };
    let mut encoded = Vec::new();
    into_writer(&metadata, &mut encoded)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to encode metadata"))?;
    fs.write(&path!("device-info.cbor"), &encoded)
        .map_err(map_fs_error)
}

fn generate_attestation_certificate(
    identity: &IdentityConfig<'_>,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;
    let secret = SecretKey::random(&mut rng);
    let private_key = secret.to_bytes().to_vec();
    let pkcs8 = secret
        .to_pkcs8_der()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("pkcs8 error: {err}")))?;
    let key_pair = KeyPair::from_der(pkcs8.as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("key pair error: {err}")))?;

    let mut params = CertificateParams::new(vec![identity.product.to_string()]);
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params
        .distinguished_name
        .push(DnType::OrganizationName, identity.manufacturer);
    params
        .distinguished_name
        .push(DnType::CommonName, identity.product);
    params
        .subject_alt_names
        .push(SanType::DnsName(identity.product.to_string()));
    params.serial_number = Some(SerialNumber::from(identity.serial.as_bytes().to_vec()));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_pair = Some(key_pair);

    let certificate = Certificate::from_params(params)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("certificate error: {err}")))?;
    let der = certificate.serialize_der().map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("certificate encode error: {err}"),
        )
    })?;

    Ok((private_key, der))
}

impl EncryptedFileStorage {
    fn new(file: File, key: [u8; 32], nonce: [u8; 24]) -> Self {
        Self { file, key, nonce }
    }

    fn apply_keystream(&self, offset: usize, buf: &mut [u8]) {
        let key = Key::from_slice(&self.key);
        let nonce = XNonce::from_slice(&self.nonce);
        let mut cipher = XChaCha20::new(key, nonce);
        cipher.seek(offset as u64);
        cipher.apply_keystream(buf);
    }
}

impl Storage for EncryptedFileStorage {
    const READ_SIZE: usize = READ_SIZE;
    const WRITE_SIZE: usize = WRITE_SIZE;
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    const BLOCK_COUNT: usize = BLOCK_COUNT;
    type CACHE_SIZE = consts::U256;
    type LOOKAHEAD_SIZE = consts::U4;

    fn read(&mut self, offset: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
        debug_assert!(offset % Self::READ_SIZE == 0);
        debug_assert!(buf.len() % Self::READ_SIZE == 0);
        read_exact_at(&self.file, offset as u64, buf).map_err(|_| lfs_io_error())?;
        self.apply_keystream(offset, buf);
        Ok(buf.len())
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
        debug_assert!(offset % Self::WRITE_SIZE == 0);
        debug_assert!(data.len() % Self::WRITE_SIZE == 0);
        let mut buf = data.to_vec();
        self.apply_keystream(offset, &mut buf);
        write_exact_at(&self.file, offset as u64, &buf).map_err(|_| lfs_io_error())?;
        Ok(buf.len())
    }

    fn erase(&mut self, offset: usize, len: usize) -> littlefs2::io::Result<usize> {
        debug_assert!(offset % Self::BLOCK_SIZE == 0);
        debug_assert!(len % Self::BLOCK_SIZE == 0);
        let mut buf = vec![0xffu8; len];
        self.apply_keystream(offset, &mut buf);
        write_exact_at(&self.file, offset as u64, &buf).map_err(|_| lfs_io_error())?;
        Ok(len)
    }
}
