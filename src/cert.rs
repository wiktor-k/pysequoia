use std::borrow::Cow;
use std::sync::{Arc, Mutex, MutexGuard};

use once_cell::sync::Lazy;
use pyo3::prelude::*;
use sequoia_openpgp::Packet;
use sequoia_openpgp::cert::{self, prelude::*};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::signature::subpacket::NotationDataFlags;
use sequoia_openpgp::packet::{UserID, signature};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::{Policy, StandardPolicy};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{KeyFlags, ReasonForRevocation, RevocationStatus, SignatureType};

use crate::notation::Notation;
use crate::signer::PySigner;
use crate::user_id::UserId;

static DEFAULT_POLICY: Lazy<Arc<Mutex<Box<dyn Policy>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Box::new(StandardPolicy::new()))));

/// An OpenPGP certificate (public key with associated user IDs, subkeys, and signatures).
#[derive(Clone)]
#[pyclass(from_py_object)]
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

    pub fn policy(&self) -> MutexGuard<'_, Box<dyn Policy>> {
        self.policy.lock().unwrap()
    }
}

/// The OpenPGP profile to use when generating certificates.
///
/// Controls which packet format and algorithms are used.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[pyclass(from_py_object, eq)]
pub enum Profile {
    #[default]
    RFC4880,
    RFC9580,
}

impl From<Profile> for sequoia_openpgp::Profile {
    fn from(profile: Profile) -> Self {
        match profile {
            Profile::RFC4880 => sequoia_openpgp::Profile::RFC4880,
            Profile::RFC9580 => sequoia_openpgp::Profile::RFC9580,
        }
    }
}

pub mod secret;

#[pymethods]
impl Cert {
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

    /// Parse multiple certificates from a file on disk.
    ///
    /// Returns a list of all certificates found in the file.
    /// The file may be binary or ASCII-armored.
    #[staticmethod]
    pub fn split_file(path: String) -> PyResult<Vec<Self>> {
        let parser = CertParser::from_file(path)?;
        let mut results = vec![];
        for item in parser {
            results.push(item?.into());
        }
        Ok(results)
    }

    /// Parse multiple certificates from a byte string.
    ///
    /// Returns a list of all certificates found in the data.
    /// The bytes may be binary or ASCII-armored.
    #[staticmethod]
    pub fn split_bytes(bytes: &[u8]) -> PyResult<Vec<Self>> {
        let parser = CertParser::from_bytes(&bytes)?;
        let mut results = vec![];
        for item in parser {
            results.push(item?.into());
        }
        Ok(results)
    }

    /// Generate a new certificate with a certification-capable primary key,
    /// a signing subkey, and an encryption subkey.
    ///
    /// The generated certificate has a validity period of 3 years.
    #[staticmethod]
    #[pyo3(signature = (user_id=None, user_ids=None, profile=None))]
    pub fn generate(
        user_id: Option<&str>,
        user_ids: Option<Vec<String>>,
        profile: Option<Profile>,
    ) -> PyResult<Self> {
        let mut builder = CertBuilder::new()
            .set_profile(profile.unwrap_or_default().into())?
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

    /// Whether this certificate contains secret key material.
    #[getter]
    pub fn has_secret_keys(&self) -> bool {
        self.cert.is_tsk()
    }

    /// Access the secret key material, if present.
    ///
    /// Returns `None` if the certificate does not contain secret keys.
    #[getter]
    pub fn secrets(&self) -> Option<secret::Tsk> {
        if self.cert.is_tsk() {
            Some(secret::Tsk::new(self.cert.clone(), &self.policy))
        } else {
            None
        }
    }

    /// Merge another certificate into this one, combining their packets.
    ///
    /// Both certificates must have the same primary key fingerprint.
    pub fn merge(&self, new_cert: &Cert) -> PyResult<Cert> {
        let merged_cert = self.cert().clone().merge_public(new_cert.cert().clone())?;
        Ok(merged_cert.into())
    }

    /// Add a User ID to this certificate, certified by the given signer.
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

    /// Create a revocation signature for the given User ID.
    pub fn revoke_user_id(
        &mut self,
        user_id: &UserId,
        mut certifier: PySigner,
    ) -> PyResult<crate::signature::Sig> {
        let userid = UserID::from(user_id.__str__());
        let builder = signature::SignatureBuilder::new(SignatureType::CertificationRevocation);
        Ok(userid.bind(&mut certifier, &self.cert, builder)?.into())
    }

    /// Set the expiration time of this certificate.
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

    /// The expiration time of this certificate, or `None` if it does not expire.
    #[getter]
    pub fn expiration(&self) -> PyResult<Option<chrono::DateTime<chrono::Utc>>> {
        Ok(self
            .cert
            .primary_key()
            .with_policy(&**self.policy(), None)?
            .key_expiration_time()
            .map(|exp| exp.into()))
    }

    /// Return the ASCII-armored public key representation of this certificate.
    pub fn __str__(&self) -> PyResult<String> {
        let armored = self.cert.armored();
        Ok(String::from_utf8(armored.to_vec()?)?)
    }

    pub fn __repr__(&self) -> String {
        format!("<Cert fingerprint={}>", self.cert.fingerprint())
    }

    /// The fingerprint of this certificate's primary key, as a lowercase hex string.
    #[getter]
    pub fn fingerprint(&self) -> PyResult<String> {
        Ok(format!("{:x}", self.cert.fingerprint()))
    }

    /// The non-revoked User IDs on this certificate.
    #[getter]
    pub fn user_ids(&self) -> PyResult<Vec<UserId>> {
        let policy = &**self.policy();
        let cert = self.cert.with_policy(policy, None)?;
        cert.userids().revoked(false).map(UserId::new).collect()
    }

    /// Set notation data on the first User ID's binding signature.
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

    /// Return the raw binary encoding of this certificate.
    pub fn __bytes__(&self) -> PyResult<Cow<'_, [u8]>> {
        Ok(self.cert.to_vec()?.into())
    }

    /// Create a revocation signature for this certificate.
    pub fn revoke(&self, mut certifier: PySigner) -> PyResult<crate::signature::Sig> {
        let signature = self
            .cert
            .revoke(&mut certifier, ReasonForRevocation::Unspecified, &[])?;
        Ok(crate::signature::Sig::new(signature))
    }

    /// Whether this certificate has been revoked.
    #[getter]
    pub fn is_revoked(&self) -> bool {
        self.cert.revocation_status(&**self.policy(), None) != RevocationStatus::NotAsFarAsWeKnow
    }
}
