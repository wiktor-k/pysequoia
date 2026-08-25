use std::borrow::Cow;
use std::sync::{Arc, Mutex, MutexGuard};

use pyo3::prelude::*;
use sequoia_openpgp::parse::Parse as _;
use sequoia_openpgp::types::KeyFlags;
use sequoia_openpgp::{cert, policy::Policy, serialize::SerializeInto};

use crate::cert::{DEFAULT_POLICY, Profile};
use crate::decrypt;
use crate::signer::PySigner;

/// The cipher suite to use when generating keys.
///
/// Controls which cryptographic algorithms are used for the primary key and subkeys.
/// The PQC (post-quantum cryptography) suites require `Profile.RFC9580`.
#[derive(Clone, Default, PartialEq, Eq)]
#[pyclass(from_py_object, eq)]
#[expect(
    non_camel_case_types,
    reason = "variant names matching specification and upstream"
)]
pub enum CipherSuite {
    /// EdDSA and ECDH over Curve25519 (default)
    #[default]
    Cv25519,
    /// EdDSA and ECDH over Curve448
    Cv448,
    /// 2048-bit RSA
    RSA2k,
    /// 3072-bit RSA
    RSA3k,
    /// 4096-bit RSA
    RSA4k,
    /// ECDSA and ECDH over NIST P-256
    P256,
    /// ECDSA and ECDH over NIST P-384
    P384,
    /// ECDSA and ECDH over NIST P-521
    P521,
    /// Post-quantum: ML-DSA-65 + Ed25519 signing, ML-KEM-768 + X25519 encryption (v6 only)
    MLDSA65_Ed25519,
    /// Post-quantum: ML-DSA-87 + Ed448 signing, ML-KEM-1024 + X448 encryption (v6 only)
    MLDSA87_Ed448,
}

impl From<CipherSuite> for cert::CipherSuite {
    fn from(cs: CipherSuite) -> Self {
        match cs {
            CipherSuite::Cv25519 => Self::Cv25519,
            CipherSuite::Cv448 => Self::Cv448,
            CipherSuite::RSA2k => Self::RSA2k,
            CipherSuite::RSA3k => Self::RSA3k,
            CipherSuite::RSA4k => Self::RSA4k,
            CipherSuite::P256 => Self::P256,
            CipherSuite::P384 => Self::P384,
            CipherSuite::P521 => Self::P521,
            CipherSuite::MLDSA65_Ed25519 => Self::MLDSA65_Ed25519,
            CipherSuite::MLDSA87_Ed448 => Self::MLDSA87_Ed448,
        }
    }
}

/// A certificate that contains secret key material.
///
/// Provides access to signing, certification, and decryption operations
/// that require private keys.
#[pyclass]
pub struct Tsk {
    cert: cert::Cert,
    policy: Arc<Mutex<Box<dyn Policy>>>,
}

impl Tsk {
    pub fn new(cert: cert::Cert, policy: &Arc<Mutex<Box<dyn Policy>>>) -> Self {
        Self {
            cert,
            policy: Arc::clone(policy),
        }
    }
    pub fn policy(&self) -> MutexGuard<'_, Box<dyn Policy>> {
        self.policy.lock().unwrap()
    }
}

impl From<cert::Cert> for Tsk {
    fn from(cert: cert::Cert) -> Self {
        Self {
            cert,
            policy: Arc::clone(&DEFAULT_POLICY),
        }
    }
}

#[pymethods]
impl Tsk {
    /// Generate a new TSK with a certification-capable primary key,
    /// a signing subkey, and an encryption subkey.
    ///
    /// The generated certificate does not expire unless explicitly instructed.
    #[staticmethod]
    #[pyo3(signature = (user_id=None, user_ids=None, profile=None, cipher_suite=None, validity_seconds=None, *, signing_algorithm=None, encryption_algorithm=None))]
    pub fn generate(
        user_id: Option<&str>,
        user_ids: Option<Vec<String>>,
        profile: Option<Profile>,
        cipher_suite: Option<CipherSuite>,
        validity_seconds: Option<u64>,
        signing_algorithm: Option<crate::types::SigningAlgorithm>,
        encryption_algorithm: Option<crate::types::EncryptionAlgorithm>,
    ) -> PyResult<Self> {
        let mut builder = cert::CertBuilder::new()
            .set_profile(profile.unwrap_or_default().into())?
            .set_cipher_suite(cipher_suite.unwrap_or_default().into())
            .set_primary_key_flags(KeyFlags::empty().set_certification())
            .add_signing_subkey()
            .add_subkey(
                KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption(),
                None,
                None,
            );
        if let Some(signing_algo) = signing_algorithm {
            builder = builder.set_signing_algorithm(signing_algo.into());
        }
        if let Some(encryption_algo) = encryption_algorithm {
            builder = builder.set_encryption_algorithm(encryption_algo.into());
        }
        if let Some(validity_seconds) = validity_seconds {
            builder = builder.set_validity_period(std::time::Duration::new(validity_seconds, 0))
        }
        if let Some(u) = user_id {
            builder = builder.add_userid(u);
        }
        if let Some(user_ids) = user_ids {
            for user_id in user_ids {
                builder = builder.add_userid(user_id);
            }
        }

        Ok(builder.generate()?.0.into())
    }

    /// Parse a certificate from a file on disk.
    ///
    /// The file may be binary or ASCII-armored.
    #[staticmethod]
    pub fn from_file(path: String) -> PyResult<Self> {
        Ok(cert::Cert::from_file(path)?.into())
    }

    /// Parse a certificate from a byte string.
    ///
    /// The bytes may be binary or ASCII-armored.
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        Ok(cert::Cert::from_bytes(bytes)?.into())
    }

    /// Build a certificate from a sequence of OpenPGP packets.
    ///
    /// The packets must form a valid certificate (a primary key followed by
    /// its associated user IDs, user attributes, subkeys, and signatures).
    #[staticmethod]
    pub fn from_packets(packets: Vec<crate::packet::PyPacket>) -> PyResult<Self> {
        let sq_packets = packets.into_iter().map(|p| p.into_inner());
        Ok(cert::Cert::from_packets(sq_packets)?.into())
    }

    /// Return the ASCII-armored secret key representation (Transferable Secret Key).
    pub fn __str__(&self) -> PyResult<String> {
        let armored = self.cert.as_tsk().armored();
        Ok(String::from_utf8(armored.to_vec()?)?)
    }

    pub fn __repr__(&self) -> String {
        format!("<Tsk fingerprint={}>", self.cert.fingerprint())
    }

    /// Return the raw binary encoding of this certificate.
    pub fn __bytes__(&self) -> PyResult<Cow<'_, [u8]>> {
        Ok(self.cert.as_tsk().to_vec()?.into())
    }

    /// Extracts public parts of this TSK.
    pub fn extract_certificate(&self) -> PyResult<crate::cert::Cert> {
        Ok(self.cert.clone().into())
    }

    /// Get a signer using this certificate's signing component key.
    ///
    /// If the secret key is password-protected, provide the password to decrypt it.
    #[pyo3(signature = (password=None))]
    pub fn signer(&self, password: Option<String>) -> PyResult<PySigner> {
        if let Some(key) = self
            .cert
            .keys()
            .secret()
            .with_policy(&**self.policy(), None)
            .alive()
            .revoked(false)
            .for_signing()
            .next()
        {
            let mut key = key.key().clone();
            if let Some(password) = password {
                key = key.decrypt_secret(&(password[..]).into())?;
            }
            let keypair = key.into_keypair()?;
            Ok(PySigner::new(Box::new(keypair)))
        } else {
            Err(anyhow::anyhow!("No suitable signing subkey for {}", self.cert).into())
        }
    }

    /// Get a certifier using this certificate's certification-capable primary key.
    ///
    /// If the secret key is password-protected, provide the password to decrypt it.
    #[pyo3(signature = (password=None))]
    pub fn certifier(&self, password: Option<String>) -> PyResult<PySigner> {
        if let Some(key) = self
            .cert
            .keys()
            .secret()
            .with_policy(&**self.policy(), None)
            .alive()
            .revoked(false)
            .for_certification()
            .next()
        {
            let mut key = key.key().clone();
            if let Some(password) = password {
                key = key.decrypt_secret(&(password[..]).into())?;
            }
            let keypair = key.into_keypair()?;
            Ok(PySigner::new(Box::new(keypair)))
        } else {
            Err(anyhow::anyhow!("No suitable certifying key for {}", self.cert).into())
        }
    }

    /// Get a decryptor using this certificate's encryption component key.
    ///
    /// If the secret key is password-protected, provide the password to decrypt it.
    #[pyo3(signature = (password=None))]
    pub fn decryptor(&self, password: Option<String>) -> PyResult<decrypt::PyDecryptor> {
        if let Some(key) = self
            .cert
            .keys()
            .secret()
            .with_policy(&**self.policy(), None)
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .for_storage_encryption()
            .next()
        {
            let mut key = key.key().clone();
            if let Some(password) = password {
                key = key.decrypt_secret(&(password[..]).into())?;
            }
            let keypair = key.into_keypair()?;
            Ok(decrypt::PyDecryptor::new(Box::new(keypair)))
        } else {
            Err(anyhow::anyhow!("No suitable decryption subkey for {}", self.cert).into())
        }
    }
}
