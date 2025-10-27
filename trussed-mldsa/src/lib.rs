//! Safe Rust wrapper around the C ML‑DSA stub implementation.
//!
//! The C functions defined in `mldsa-native/mldsa.c` provide simple
//! parameterized key generation and signing for the ML‑DSA signature
//! scheme.  They do **not** implement the actual ML‑DSA algorithm but
//! instead fill keys and signatures with pseudo‑random bytes.  Use
//! [`ParamSet`] to select the desired parameter set.

use core::ffi::c_int;
use core::ptr;
use zeroize::Zeroize;

#[cfg(feature = "mldsa44")]
extern "C" {
    fn mldsa44_sizes(pk_len: *mut usize, sk_len: *mut usize, sig_len: *mut usize) -> c_int;
    fn mldsa44_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn mldsa44_sign(
        sig: *mut u8,
        sig_len: *mut usize,
        msg: *const u8,
        msg_len: usize,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(feature = "mldsa65")]
extern "C" {
    fn mldsa65_sizes(pk_len: *mut usize, sk_len: *mut usize, sig_len: *mut usize) -> c_int;
    fn mldsa65_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn mldsa65_sign(
        sig: *mut u8,
        sig_len: *mut usize,
        msg: *const u8,
        msg_len: usize,
        sk: *const u8,
    ) -> c_int;
}

#[cfg(feature = "mldsa87")]
extern "C" {
    fn mldsa87_sizes(pk_len: *mut usize, sk_len: *mut usize, sig_len: *mut usize) -> c_int;
    fn mldsa87_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn mldsa87_sign(
        sig: *mut u8,
        sig_len: *mut usize,
        msg: *const u8,
        msg_len: usize,
        sk: *const u8,
    ) -> c_int;
}

/// ML‑DSA parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamSet {
    /// Parameter set ML‑DSA‑44 (security level 2).
    MLDsa44,
    /// Parameter set ML‑DSA‑65 (security level 3).
    MLDsa65,
    /// Parameter set ML‑DSA‑87 (security level 5).
    MLDsa87,
}

/// Public key wrapper.  The bytes can be accessed via `.0`.  Note that
/// the underlying C code uses raw bytes; no structure is imposed here.
#[derive(Debug, Clone)]
pub struct PublicKey(pub Vec<u8>);

/// Secret key wrapper.  On drop the secret key is zeroized.
#[derive(Debug)]
pub struct SecretKey(pub Vec<u8>);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Return the lengths of the public key, secret key and maximum signature for
/// the given parameter set.  Panics if the underlying C function fails.
fn sizes(ps: ParamSet) -> (usize, usize, usize) {
    unsafe {
        let mut pk_len = 0usize;
        let mut sk_len = 0usize;
        let mut sig_len = 0usize;
        let rc = match ps {
            ParamSet::MLDsa44 => {
                #[cfg(feature = "mldsa44")]
                {
                    mldsa44_sizes(&mut pk_len, &mut sk_len, &mut sig_len)
                }
                #[cfg(not(feature = "mldsa44"))]
                {
                    panic!("Feature mldsa44 is not enabled");
                }
            }
            ParamSet::MLDsa65 => {
                #[cfg(feature = "mldsa65")]
                {
                    mldsa65_sizes(&mut pk_len, &mut sk_len, &mut sig_len)
                }
                #[cfg(not(feature = "mldsa65"))]
                {
                    panic!("Feature mldsa65 is not enabled");
                }
            }
            ParamSet::MLDsa87 => {
                #[cfg(feature = "mldsa87")]
                {
                    mldsa87_sizes(&mut pk_len, &mut sk_len, &mut sig_len)
                }
                #[cfg(not(feature = "mldsa87"))]
                {
                    panic!("Feature mldsa87 is not enabled");
                }
            }
        };
        assert_eq!(rc, 0, "mldsa sizes function returned error");
        (pk_len, sk_len, sig_len)
    }
}

/// Generate a public/secret keypair for the given parameter set.
pub fn keypair(ps: ParamSet) -> (PublicKey, SecretKey) {
    let (pk_len, sk_len, _sig_len) = sizes(ps);
    let mut pk = vec![0u8; pk_len];
    let mut sk = vec![0u8; sk_len];
    unsafe {
        let rc = match ps {
            ParamSet::MLDsa44 => {
                #[cfg(feature = "mldsa44")]
                {
                    mldsa44_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                }
                #[cfg(not(feature = "mldsa44"))]
                {
                    panic!("Feature mldsa44 is not enabled");
                }
            }
            ParamSet::MLDsa65 => {
                #[cfg(feature = "mldsa65")]
                {
                    mldsa65_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                }
                #[cfg(not(feature = "mldsa65"))]
                {
                    panic!("Feature mldsa65 is not enabled");
                }
            }
            ParamSet::MLDsa87 => {
                #[cfg(feature = "mldsa87")]
                {
                    mldsa87_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                }
                #[cfg(not(feature = "mldsa87"))]
                {
                    panic!("Feature mldsa87 is not enabled");
                }
            }
        };
        assert_eq!(rc, 0, "mldsa keypair returned error");
    }
    (PublicKey(pk), SecretKey(sk))
}

/// Sign a message using the provided secret key and parameter set.  Returns a
/// vector containing the raw signature bytes.
pub fn sign(ps: ParamSet, sk: &SecretKey, msg: &[u8]) -> Vec<u8> {
    let (_pk_len, _sk_len, sig_max) = sizes(ps);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len: usize = 0;
    unsafe {
        let rc = match ps {
            ParamSet::MLDsa44 => {
                #[cfg(feature = "mldsa44")]
                {
                    mldsa44_sign(
                        sig.as_mut_ptr(),
                        &mut sig_len,
                        msg.as_ptr(),
                        msg.len(),
                        sk.0.as_ptr(),
                    )
                }
                #[cfg(not(feature = "mldsa44"))]
                {
                    panic!("Feature mldsa44 is not enabled");
                }
            }
            ParamSet::MLDsa65 => {
                #[cfg(feature = "mldsa65")]
                {
                    mldsa65_sign(
                        sig.as_mut_ptr(),
                        &mut sig_len,
                        msg.as_ptr(),
                        msg.len(),
                        sk.0.as_ptr(),
                    )
                }
                #[cfg(not(feature = "mldsa65"))]
                {
                    panic!("Feature mldsa65 is not enabled");
                }
            }
            ParamSet::MLDsa87 => {
                #[cfg(feature = "mldsa87")]
                {
                    mldsa87_sign(
                        sig.as_mut_ptr(),
                        &mut sig_len,
                        msg.as_ptr(),
                        msg.len(),
                        sk.0.as_ptr(),
                    )
                }
                #[cfg(not(feature = "mldsa87"))]
                {
                    panic!("Feature mldsa87 is not enabled");
                }
            }
        };
        assert_eq!(rc, 0, "mldsa sign returned error");
    }
    sig.truncate(sig_len);
    sig
}