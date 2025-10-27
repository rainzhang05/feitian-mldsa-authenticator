//! Safe Rust wrapper around the liboqs ML-DSA signature implementations.
//!
//! The wrapper exposes the ML-DSA-44/65/87 variants with minimal
//! overhead while ensuring that secret keys are wiped from memory on
//! drop.  The FFI bindings panic when liboqs reports an error, which is
//! desirable for development builds where failing to produce a
//! signature should abort the test suite immediately.

use zeroize::Zeroize;

#[cfg(feature = "mldsa44")]
extern "C" {
    fn OQS_SIG_ml_dsa_44_keypair(public_key: *mut u8, secret_key: *mut u8) -> i32;
    fn OQS_SIG_ml_dsa_44_sign(
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        secret_key: *const u8,
    ) -> i32;
    fn OQS_SIG_ml_dsa_44_verify(
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
    ) -> i32;
}

#[cfg(feature = "mldsa65")]
extern "C" {
    fn OQS_SIG_ml_dsa_65_keypair(public_key: *mut u8, secret_key: *mut u8) -> i32;
    fn OQS_SIG_ml_dsa_65_sign(
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        secret_key: *const u8,
    ) -> i32;
    fn OQS_SIG_ml_dsa_65_verify(
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
    ) -> i32;
}

#[cfg(feature = "mldsa87")]
extern "C" {
    fn OQS_SIG_ml_dsa_87_keypair(public_key: *mut u8, secret_key: *mut u8) -> i32;
    fn OQS_SIG_ml_dsa_87_sign(
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        secret_key: *const u8,
    ) -> i32;
    fn OQS_SIG_ml_dsa_87_verify(
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
    ) -> i32;
}

/// ML-DSA parameter sets supported by this wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamSet {
    MLDsa44,
    MLDsa65,
    MLDsa87,
}

/// Public key wrapper.
#[derive(Debug, Clone)]
pub struct PublicKey(pub Vec<u8>);

/// Secret key wrapper.  The key material is zeroised on drop.
#[derive(Debug)]
pub struct SecretKey(pub Vec<u8>);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Return the buffer lengths required by the parameter set.
fn lengths(ps: ParamSet) -> (usize, usize, usize) {
    match ps {
        ParamSet::MLDsa44 => (1312, 2560, 2420),
        ParamSet::MLDsa65 => (1952, 4032, 3309),
        ParamSet::MLDsa87 => (2592, 4896, 4627),
    }
}

/// Generate an ML-DSA keypair.
pub fn keypair(ps: ParamSet) -> (PublicKey, SecretKey) {
    let (pk_len, sk_len, _sig_len) = lengths(ps);
    let mut pk = vec![0u8; pk_len];
    let mut sk = vec![0u8; sk_len];
    unsafe {
        let rc = match ps {
            ParamSet::MLDsa44 => {
                #[cfg(feature = "mldsa44")]
                {
                    OQS_SIG_ml_dsa_44_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                }
                #[cfg(not(feature = "mldsa44"))]
                {
                    panic!("feature mldsa44 is not enabled");
                }
            }
            ParamSet::MLDsa65 => {
                #[cfg(feature = "mldsa65")]
                {
                    OQS_SIG_ml_dsa_65_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                }
                #[cfg(not(feature = "mldsa65"))]
                {
                    panic!("feature mldsa65 is not enabled");
                }
            }
            ParamSet::MLDsa87 => {
                #[cfg(feature = "mldsa87")]
                {
                    OQS_SIG_ml_dsa_87_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                }
                #[cfg(not(feature = "mldsa87"))]
                {
                    panic!("feature mldsa87 is not enabled");
                }
            }
        };
        assert_eq!(rc, 0, "liboqs keypair call failed");
    }
    (PublicKey(pk), SecretKey(sk))
}

/// Sign a message with the supplied secret key.
pub fn sign(ps: ParamSet, sk: &SecretKey, message: &[u8]) -> Vec<u8> {
    let (_pk_len, _sk_len, sig_len) = lengths(ps);
    let mut sig = vec![0u8; sig_len];
    let mut actual_len: usize = sig_len;
    unsafe {
        let rc = match ps {
            ParamSet::MLDsa44 => {
                #[cfg(feature = "mldsa44")]
                {
                    OQS_SIG_ml_dsa_44_sign(
                        sig.as_mut_ptr(),
                        &mut actual_len,
                        message.as_ptr(),
                        message.len(),
                        sk.0.as_ptr(),
                    )
                }
                #[cfg(not(feature = "mldsa44"))]
                {
                    panic!("feature mldsa44 is not enabled");
                }
            }
            ParamSet::MLDsa65 => {
                #[cfg(feature = "mldsa65")]
                {
                    OQS_SIG_ml_dsa_65_sign(
                        sig.as_mut_ptr(),
                        &mut actual_len,
                        message.as_ptr(),
                        message.len(),
                        sk.0.as_ptr(),
                    )
                }
                #[cfg(not(feature = "mldsa65"))]
                {
                    panic!("feature mldsa65 is not enabled");
                }
            }
            ParamSet::MLDsa87 => {
                #[cfg(feature = "mldsa87")]
                {
                    OQS_SIG_ml_dsa_87_sign(
                        sig.as_mut_ptr(),
                        &mut actual_len,
                        message.as_ptr(),
                        message.len(),
                        sk.0.as_ptr(),
                    )
                }
                #[cfg(not(feature = "mldsa87"))]
                {
                    panic!("feature mldsa87 is not enabled");
                }
            }
        };
        assert_eq!(rc, 0, "liboqs sign call failed");
    }
    sig.truncate(actual_len);
    sig
}

/// Verify a signature over the message using the provided public key.
pub fn verify(ps: ParamSet, pk: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    unsafe {
        let rc = match ps {
            ParamSet::MLDsa44 => {
                #[cfg(feature = "mldsa44")]
                {
                    OQS_SIG_ml_dsa_44_verify(
                        message.as_ptr(),
                        message.len(),
                        signature.as_ptr(),
                        signature.len(),
                        pk.0.as_ptr(),
                    )
                }
                #[cfg(not(feature = "mldsa44"))]
                {
                    panic!("feature mldsa44 is not enabled");
                }
            }
            ParamSet::MLDsa65 => {
                #[cfg(feature = "mldsa65")]
                {
                    OQS_SIG_ml_dsa_65_verify(
                        message.as_ptr(),
                        message.len(),
                        signature.as_ptr(),
                        signature.len(),
                        pk.0.as_ptr(),
                    )
                }
                #[cfg(not(feature = "mldsa65"))]
                {
                    panic!("feature mldsa65 is not enabled");
                }
            }
            ParamSet::MLDsa87 => {
                #[cfg(feature = "mldsa87")]
                {
                    OQS_SIG_ml_dsa_87_verify(
                        message.as_ptr(),
                        message.len(),
                        signature.as_ptr(),
                        signature.len(),
                        pk.0.as_ptr(),
                    )
                }
                #[cfg(not(feature = "mldsa87"))]
                {
                    panic!("feature mldsa87 is not enabled");
                }
            }
        };
        rc == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(ps: ParamSet) {
        let (pk, sk) = keypair(ps);
        let message = b"post-quantum authentication";
        let signature = sign(ps, &sk, message);
        assert!(
            verify(ps, &pk, message, &signature),
            "verification failed for {:?}",
            ps
        );
    }

    #[test]
    fn mldsa44_roundtrip() {
        roundtrip(ParamSet::MLDsa44);
    }

    #[test]
    fn mldsa65_roundtrip() {
        roundtrip(ParamSet::MLDsa65);
    }

    #[test]
    fn mldsa87_roundtrip() {
        roundtrip(ParamSet::MLDsa87);
    }
}
