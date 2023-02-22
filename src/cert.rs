use openpgp::policy::{Policy, StandardPolicy};
use openpgp::serialize::SerializeInto;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::decrypt;
use crate::signer::PySigner;

#[pyclass]
pub struct Cert {
    cert: openpgp::cert::Cert,
    policy: Box<dyn Policy>,
}

impl From<openpgp::cert::Cert> for Cert {
    fn from(cert: openpgp::cert::Cert) -> Self {
        Self {
            cert,
            policy: Box::new(StandardPolicy::new()),
        }
    }
}

impl Cert {
    pub fn cert(&self) -> &openpgp::cert::Cert {
        &self.cert
    }

    pub fn policy(&self) -> &dyn Policy {
        &*self.policy
    }
}

#[pymethods]
impl Cert {
    #[staticmethod]
    pub fn from_file(path: String) -> PyResult<Self> {
        use openpgp::parse::Parse;
        Ok(openpgp::cert::Cert::from_file(path)?.into())
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        use openpgp::parse::Parse;
        Ok(openpgp::cert::Cert::from_bytes(bytes)?.into())
    }

    #[staticmethod]
    pub fn generate(user_id: &str) -> PyResult<Self> {
        Ok(
            openpgp::cert::CertBuilder::general_purpose(None, Some(user_id))
                .generate()?
                .0
                .into(),
        )
    }

    pub fn merge(&self, new_cert: &Cert) -> PyResult<Cert> {
        Ok(crate::utils::merge_certs(self, new_cert)?)
    }

    pub fn __str__(&self) -> PyResult<String> {
        let armored = self.cert.armored();
        Ok(String::from_utf8(armored.to_vec()?)?)
    }

    pub fn __repr__(&self) -> String {
        format!("<Cert fingerprint={}>", self.cert.fingerprint())
    }

    #[getter]
    pub fn fingerprint(&self) -> PyResult<String> {
        Ok(format!("{:x}", self.cert.fingerprint()))
    }

    pub fn signer(&self, password: Option<String>) -> PyResult<PySigner> {
        if let Some(key) = self
            .cert
            .keys()
            .secret()
            .with_policy(&*self.policy, None)
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

    pub fn decryptor(&self, password: Option<String>) -> PyResult<decrypt::PyDecryptor> {
        if let Some(key) = self
            .cert
            .keys()
            .secret()
            .with_policy(&*self.policy, None)
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
