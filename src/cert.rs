use openpgp::cert::prelude::*;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::policy::{Policy, StandardPolicy};
use openpgp::serialize::SerializeInto;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::decrypt;
use crate::notation::Notation;
use crate::signer::PySigner;
use crate::user_id::UserId;

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
        let merged_cert = self.cert().clone().merge_public(new_cert.cert().clone())?;
        Ok(merged_cert.into())
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

    #[getter]
    pub fn user_ids(&self) -> PyResult<Vec<UserId>> {
        let cert = self.cert.with_policy(&*self.policy, None)?;
        Ok(cert.userids().map(UserId::new).collect())
    }

    pub fn set_notations(&self, mut signer: PySigner, notations: Vec<Notation>) -> PyResult<Self> {
        let cert = self.cert.with_policy(&*self.policy, None)?;

        let ua = cert.userids().next().unwrap();
        let mut builder = SignatureBuilder::from(ua.binding_signature().clone());

        let cert = if !notations.is_empty() {
            builder = builder.set_notation(
                notations[0].key(),
                notations[0].value(),
                NotationDataFlags::empty().set_human_readable(),
                false,
            )?;

            for notation in &notations[1..] {
                builder = builder.add_notation(
                    notation.key(),
                    notation.value(),
                    NotationDataFlags::empty().set_human_readable(),
                    false,
                )?;
            }

            let new_sig = builder.sign_userid_binding(&mut signer, None, ua.userid())?;

            self.cert.clone().insert_packets(vec![new_sig])?
        } else {
            self.cert.clone()
        };

        Ok(cert.into())
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
