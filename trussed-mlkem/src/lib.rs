//! Safe wrapper around the liboqs ML-KEM implementations.
//!
//! The functions provided here expose the ML-KEM-512/768/1024 key
//! encapsulation mechanisms through a safe Rust API.  All secret
//! material is zeroised on drop and the wrappers panic if the
//! underlying FFI call fails, ensuring that test failures surface
//! immediately during development builds.

use zeroize::Zeroize;

#[cfg(feature = "mlkem512")]
extern "C" {
    fn OQS_KEM_ml_kem_512_keypair(public_key: *mut u8, secret_key: *mut u8) -> i32;
    fn OQS_KEM_ml_kem_512_encaps(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    ) -> i32;
    fn OQS_KEM_ml_kem_512_decaps(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        secret_key: *const u8,
    ) -> i32;
}

#[cfg(feature = "mlkem768")]
extern "C" {
    fn OQS_KEM_ml_kem_768_keypair(public_key: *mut u8, secret_key: *mut u8) -> i32;
    fn OQS_KEM_ml_kem_768_encaps(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    ) -> i32;
    fn OQS_KEM_ml_kem_768_decaps(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        secret_key: *const u8,
    ) -> i32;
}

#[cfg(feature = "mlkem1024")]
extern "C" {
    fn OQS_KEM_ml_kem_1024_keypair(public_key: *mut u8, secret_key: *mut u8) -> i32;
    fn OQS_KEM_ml_kem_1024_encaps(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    ) -> i32;
    fn OQS_KEM_ml_kem_1024_decaps(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        secret_key: *const u8,
    ) -> i32;
}

/// Available ML-KEM parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamSet {
    MLKem512,
    MLKem768,
    MLKem1024,
}

/// Public key wrapper.
#[derive(Debug, Clone)]
pub struct PublicKey(pub Vec<u8>);

/// Secret key wrapper.  The key material is securely wiped on drop.
#[derive(Debug)]
pub struct SecretKey(pub Vec<u8>);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Ciphertext wrapper produced by encapsulation.
#[derive(Debug, Clone)]
pub struct Ciphertext(pub Vec<u8>);

/// Shared secret wrapper.  The bytes are cleared on drop.
#[derive(Debug, Clone)]
pub struct SharedSecret(pub Vec<u8>);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Return the lengths of the key and ciphertext buffers for a parameter set.
fn lengths(ps: ParamSet) -> (usize, usize, usize, usize) {
    match ps {
        ParamSet::MLKem512 => (800, 1632, 768, 32),
        ParamSet::MLKem768 => (1184, 2400, 1088, 32),
        ParamSet::MLKem1024 => (1568, 3168, 1568, 32),
    }
}

/// Generate an ML-KEM keypair.
pub fn keypair(ps: ParamSet) -> (PublicKey, SecretKey) {
    let (pk_len, sk_len, _ct_len, _ss_len) = lengths(ps);
    let mut pk = vec![0u8; pk_len];
    let mut sk = vec![0u8; sk_len];
    unsafe {
        let rc = match ps {
            ParamSet::MLKem512 => {
                #[cfg(feature = "mlkem512")]
                {
                    OQS_KEM_ml_kem_512_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                }
                #[cfg(not(feature = "mlkem512"))]
                {
                    panic!("feature mlkem512 is not enabled");
                }
            }
            ParamSet::MLKem768 => {
                #[cfg(feature = "mlkem768")]
                {
                    OQS_KEM_ml_kem_768_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                }
                #[cfg(not(feature = "mlkem768"))]
                {
                    panic!("feature mlkem768 is not enabled");
                }
            }
            ParamSet::MLKem1024 => {
                #[cfg(feature = "mlkem1024")]
                {
                    OQS_KEM_ml_kem_1024_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                }
                #[cfg(not(feature = "mlkem1024"))]
                {
                    panic!("feature mlkem1024 is not enabled");
                }
            }
        };
        assert_eq!(rc, 0, "liboqs keypair call failed");
    }
    (PublicKey(pk), SecretKey(sk))
}

/// Encapsulate a shared secret to the recipient's public key.
pub fn encapsulate(ps: ParamSet, pk: &PublicKey) -> (Ciphertext, SharedSecret) {
    let (_pk_len, _sk_len, ct_len, ss_len) = lengths(ps);
    let mut ct = vec![0u8; ct_len];
    let mut ss = vec![0u8; ss_len];
    unsafe {
        let rc = match ps {
            ParamSet::MLKem512 => {
                #[cfg(feature = "mlkem512")]
                {
                    OQS_KEM_ml_kem_512_encaps(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr())
                }
                #[cfg(not(feature = "mlkem512"))]
                {
                    panic!("feature mlkem512 is not enabled");
                }
            }
            ParamSet::MLKem768 => {
                #[cfg(feature = "mlkem768")]
                {
                    OQS_KEM_ml_kem_768_encaps(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr())
                }
                #[cfg(not(feature = "mlkem768"))]
                {
                    panic!("feature mlkem768 is not enabled");
                }
            }
            ParamSet::MLKem1024 => {
                #[cfg(feature = "mlkem1024")]
                {
                    OQS_KEM_ml_kem_1024_encaps(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.0.as_ptr())
                }
                #[cfg(not(feature = "mlkem1024"))]
                {
                    panic!("feature mlkem1024 is not enabled");
                }
            }
        };
        assert_eq!(rc, 0, "liboqs encaps call failed");
    }
    (Ciphertext(ct), SharedSecret(ss))
}

/// Errors that can occur during decapsulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecapsulationError {
    /// The ciphertext length does not match the parameter set requirements.
    InvalidCiphertextLength,
}

/// Decapsulate the shared secret from a ciphertext using the secret key.
pub fn decapsulate(
    ps: ParamSet,
    sk: &SecretKey,
    ct: &Ciphertext,
) -> Result<SharedSecret, DecapsulationError> {
    let (_pk_len, _sk_len, ct_len, ss_len) = lengths(ps);
    if ct.0.len() != ct_len {
        return Err(DecapsulationError::InvalidCiphertextLength);
    }
    let mut ss = vec![0u8; ss_len];
    unsafe {
        let rc = match ps {
            ParamSet::MLKem512 => {
                #[cfg(feature = "mlkem512")]
                {
                    OQS_KEM_ml_kem_512_decaps(ss.as_mut_ptr(), ct.0.as_ptr(), sk.0.as_ptr())
                }
                #[cfg(not(feature = "mlkem512"))]
                {
                    panic!("feature mlkem512 is not enabled");
                }
            }
            ParamSet::MLKem768 => {
                #[cfg(feature = "mlkem768")]
                {
                    OQS_KEM_ml_kem_768_decaps(ss.as_mut_ptr(), ct.0.as_ptr(), sk.0.as_ptr())
                }
                #[cfg(not(feature = "mlkem768"))]
                {
                    panic!("feature mlkem768 is not enabled");
                }
            }
            ParamSet::MLKem1024 => {
                #[cfg(feature = "mlkem1024")]
                {
                    OQS_KEM_ml_kem_1024_decaps(ss.as_mut_ptr(), ct.0.as_ptr(), sk.0.as_ptr())
                }
                #[cfg(not(feature = "mlkem1024"))]
                {
                    panic!("feature mlkem1024 is not enabled");
                }
            }
        };
        assert_eq!(rc, 0, "liboqs decaps call failed");
    }
    Ok(SharedSecret(ss))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(ps: ParamSet) {
        let (pk, sk) = keypair(ps);
        let (ct, ss_enc) = encapsulate(ps, &pk);
        let ss_dec = decapsulate(ps, &sk, &ct).expect("ciphertext should be valid");
        assert_eq!(ss_enc.0, ss_dec.0, "shared secret mismatch for {:?}", ps);

        // Reject ciphertexts with invalid length.
        let mut truncated = ct.0.clone();
        truncated.pop();
        assert!(matches!(
            decapsulate(ps, &sk, &Ciphertext(truncated)),
            Err(DecapsulationError::InvalidCiphertextLength)
        ));

        let mut oversized = ct.0.clone();
        oversized.push(0);
        assert!(matches!(
            decapsulate(ps, &sk, &Ciphertext(oversized)),
            Err(DecapsulationError::InvalidCiphertextLength)
        ));
    }

    #[test]
    fn mlkem_512_roundtrip() {
        roundtrip(ParamSet::MLKem512);
    }

    #[test]
    fn mlkem_768_roundtrip() {
        roundtrip(ParamSet::MLKem768);
    }

    #[test]
    fn mlkem_1024_roundtrip() {
        roundtrip(ParamSet::MLKem1024);
    }
}
