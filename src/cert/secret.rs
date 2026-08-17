use std::borrow::Cow;
use std::sync::{Arc, Mutex, MutexGuard};

use pyo3::prelude::*;
use sequoia_openpgp::cert::{CertBuilder, CipherSuite};
use sequoia_openpgp::parse::Parse as _;
use sequoia_openpgp::types::KeyFlags;
use sequoia_openpgp::{cert, policy::Policy, serialize::SerializeInto};

use crate::cert::{DEFAULT_POLICY, Profile};
use crate::decrypt;
use crate::signer::PySigner;

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
    /// The generated certificate has a validity period of 3 years.
    #[staticmethod]
    #[pyo3(signature = (user_id=None, user_ids=None, profile=None, validity_seconds=3 * 52 * 7 * 24 * 60 * 60))]
    pub fn generate(
        user_id: Option<&str>,
        user_ids: Option<Vec<String>>,
        profile: Option<Profile>,
        validity_seconds: Option<u64>,
    ) -> PyResult<Self> {
        let mut builder = CertBuilder::new()
            .set_profile(profile.unwrap_or_default().into())?
            .set_cipher_suite(CipherSuite::default())
            .set_primary_key_flags(KeyFlags::empty().set_certification())
            .add_signing_subkey()
            .add_subkey(
                KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption(),
                None,
                None,
            );
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
