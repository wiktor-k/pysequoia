use std::sync::{Arc, Mutex, MutexGuard};

use pyo3::prelude::*;
use sequoia_openpgp::{cert, policy::Policy, serialize::SerializeInto};

use crate::decrypt;
use crate::signer::PySigner;

/// A certificate that contains secret key material.
///
/// Provides access to signing, certification, and decryption operations
/// that require private keys.
#[pyclass]
pub struct SecretCert {
    cert: cert::Cert,
    policy: Arc<Mutex<Box<dyn Policy>>>,
}

impl SecretCert {
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

#[pymethods]
impl SecretCert {
    /// Return the ASCII-armored secret key representation (Transferable Secret Key).
    pub fn __str__(&self) -> PyResult<String> {
        let armored = self.cert.as_tsk().armored();
        Ok(String::from_utf8(armored.to_vec()?)?)
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
