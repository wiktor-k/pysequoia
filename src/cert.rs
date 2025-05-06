use std::borrow::Cow;
use std::sync::{Arc, Mutex, MutexGuard};

use once_cell::sync::Lazy;
use pyo3::prelude::*;
use sequoia_openpgp::cert::{self, prelude::*};
use sequoia_openpgp::packet::signature::subpacket::NotationDataFlags;
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::{signature, UserID};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::{Policy, StandardPolicy};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{KeyFlags, ReasonForRevocation, RevocationStatus, SignatureType};
use sequoia_openpgp::Packet;

use crate::notation::Notation;
use crate::signer::PySigner;
use crate::user_id::UserId;

static DEFAULT_POLICY: Lazy<Arc<Mutex<Box<dyn Policy>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Box::new(StandardPolicy::new()))));

#[derive(Clone)]
#[pyclass]
pub struct Cert {
    cert: cert::Cert,
    policy: Arc<Mutex<Box<dyn Policy>>>,
}

impl From<cert::Cert> for Cert {
    fn from(cert: cert::Cert) -> Self {
        Self {
            cert,
            policy: Arc::clone(&DEFAULT_POLICY),
        }
    }
}

impl Cert {
    pub fn cert(&self) -> &cert::Cert {
        &self.cert
    }

    pub fn policy(&self) -> MutexGuard<Box<dyn Policy>> {
        self.policy.lock().unwrap()
    }
}

pub mod secret;

#[pymethods]
impl Cert {
    #[staticmethod]
    pub fn from_file(path: String) -> PyResult<Self> {
        Ok(cert::Cert::from_file(path)?.into())
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        Ok(cert::Cert::from_bytes(bytes)?.into())
    }

    #[staticmethod]
    pub fn split_file(path: String) -> PyResult<Vec<Self>> {
        let parser = CertParser::from_file(path)?;
        let mut results = vec![];
        for item in parser {
            results.push(item?.into());
        }
        Ok(results)
    }

    #[staticmethod]
    pub fn split_bytes(bytes: &[u8]) -> PyResult<Vec<Self>> {
        let parser = CertParser::from_bytes(&bytes)?;
        let mut results = vec![];
        for item in parser {
            results.push(item?.into());
        }
        Ok(results)
    }

    #[staticmethod]
    #[pyo3(signature = (user_id=None, user_ids=None))]
    pub fn generate(user_id: Option<&str>, user_ids: Option<Vec<String>>) -> PyResult<Self> {
        let mut builder = CertBuilder::new()
            .set_cipher_suite(CipherSuite::default())
            .set_primary_key_flags(KeyFlags::empty().set_certification())
            .set_validity_period(std::time::Duration::new(3 * 52 * 7 * 24 * 60 * 60, 0))
            .add_signing_subkey()
            .add_subkey(
                KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption(),
                None,
                None,
            );
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

    #[getter]
    pub fn has_secret_keys(&self) -> bool {
        self.cert.is_tsk()
    }

    #[getter]
    pub fn secrets(&self) -> Option<secret::SecretCert> {
        if self.cert.is_tsk() {
            Some(secret::SecretCert::new(self.cert.clone(), &self.policy))
        } else {
            None
        }
    }

    pub fn merge(&self, new_cert: &Cert) -> PyResult<Cert> {
        let merged_cert = self.cert().clone().merge_public(new_cert.cert().clone())?;
        Ok(merged_cert.into())
    }

    pub fn add_user_id(&mut self, value: String, mut certifier: PySigner) -> PyResult<Cert> {
        let cert = self.cert.clone();
        let userid = UserID::from(value);
        let builder = signature::SignatureBuilder::new(SignatureType::PositiveCertification);
        let binding = userid.bind(&mut certifier, &cert, builder)?;

        let cert = cert
            .insert_packets(vec![Packet::from(userid), binding.into()])?
            .0;
        Ok(Cert {
            cert,
            policy: Arc::clone(&self.policy),
        })
    }

    pub fn revoke_user_id(
        &mut self,
        user_id: &UserId,
        mut certifier: PySigner,
    ) -> PyResult<crate::signature::Sig> {
        let userid = UserID::from(user_id.__str__());
        let builder = signature::SignatureBuilder::new(SignatureType::CertificationRevocation);
        Ok(userid.bind(&mut certifier, &self.cert, builder)?.into())
    }

    pub fn set_expiration(
        &mut self,
        expiration: chrono::DateTime<chrono::Utc>,
        mut certifier: PySigner,
    ) -> PyResult<Cert> {
        let cert = self.cert.clone();
        let signature = cert.set_expiration_time(
            &**self.policy(),
            None,
            &mut certifier,
            Some(expiration.into()),
        )?;

        let cert = cert.insert_packets(signature)?.0;
        Ok(Cert {
            cert,
            policy: Arc::clone(&self.policy),
        })
    }

    #[getter]
    pub fn expiration(&self) -> PyResult<Option<chrono::DateTime<chrono::Utc>>> {
        Ok(self
            .cert
            .primary_key()
            .with_policy(&**self.policy(), None)?
            .key_expiration_time()
            .map(|exp| exp.into()))
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
        let policy = &**self.policy();
        let cert = self.cert.with_policy(policy, None)?;
        cert.userids().revoked(false).map(UserId::new).collect()
    }

    pub fn set_notations(
        &self,
        mut certifier: PySigner,
        notations: Vec<Notation>,
    ) -> PyResult<Self> {
        let policy = self.policy();
        let cert = self.cert.with_policy(&**policy, None)?;

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

            let new_sig = builder.sign_userid_binding(&mut certifier, None, ua.userid())?;

            self.cert.clone().insert_packets(vec![new_sig])?.0
        } else {
            self.cert.clone()
        };

        Ok(cert.into())
    }

    pub fn __bytes__(&self) -> PyResult<Cow<[u8]>> {
        Ok(self.cert.to_vec()?.into())
    }

    pub fn revoke(&self, mut certifier: PySigner) -> PyResult<crate::signature::Sig> {
        let signature = self
            .cert
            .revoke(&mut certifier, ReasonForRevocation::Unspecified, &[])?;
        Ok(crate::signature::Sig::new(signature))
    }

    #[getter]
    pub fn is_revoked(&self) -> bool {
        self.cert.revocation_status(&**self.policy(), None) != RevocationStatus::NotAsFarAsWeKnow
    }
}
