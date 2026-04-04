use std::borrow::Cow;

mod cert;
mod decrypt;
mod encrypt;
mod notation;
mod packet;
mod sign;
mod signature;
mod signer;
mod types;
mod user_id;
mod verify;

use pyo3::prelude::*;
use sequoia_openpgp::armor::Kind;
use sequoia_openpgp::packet::Packet;
use sequoia_openpgp::parse::stream::GoodChecksum;
use sequoia_openpgp::serialize::stream::Armorer;
use sequoia_openpgp::serialize::{Marshal, stream::Message};

use crate::types::ArmorKind;

pub(crate) fn serialize<T>(p: Packet, armor_kind: T) -> sequoia_openpgp::Result<Vec<u8>>
where
    T: Into<Option<Kind>>,
{
    let mut sink = vec![];
    let mut message = Message::new(&mut sink);
    if let Some(kind) = armor_kind.into() {
        message = Armorer::new(message).kind(kind).build()?
    }
    p.serialize(&mut message)?;
    message.finalize()?;
    Ok(sink)
}

/// A verified valid signature, containing the certificate and signing key fingerprints.
#[pyclass(skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct ValidSig {
    certificate: String,
    signing_key: String,
}

impl From<GoodChecksum<'_>> for ValidSig {
    fn from(value: GoodChecksum<'_>) -> Self {
        Self {
            certificate: format!("{:x}", value.ka.cert().fingerprint()),
            signing_key: format!("{:x}", value.ka.component().fingerprint()),
        }
    }
}

#[pymethods]
impl ValidSig {
    /// The fingerprint of the certificate that made the signature.
    #[getter]
    fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The fingerprint of the specific signing key (may be a subkey).
    #[getter]
    fn signing_key(&self) -> &str {
        &self.signing_key
    }

    pub fn __repr__(&self) -> String {
        format!(
            "<ValidSig certificate={} signing_key={}>",
            self.certificate(),
            self.signing_key()
        )
    }
}

/// The result of a decryption or verification operation.
///
/// Contains the decrypted/verified content (if available) and any valid signatures found.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct Decrypted {
    valid_sigs: Vec<ValidSig>,
    content: Option<Vec<u8>>,
}

#[pymethods]
impl Decrypted {
    /// The decrypted or verified content bytes, or `None` for file-based operations.
    #[getter]
    pub fn bytes(&self) -> Option<Cow<'_, [u8]>> {
        self.content
            .as_ref()
            .map(|content| Cow::Borrowed(&content[..]))
    }

    /// The list of valid signatures found during verification.
    #[getter]
    pub fn valid_sigs(&self) -> Vec<ValidSig> {
        self.valid_sigs.clone()
    }
}

fn runtime_err<E: std::fmt::Display>(e: E) -> pyo3::PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(e.to_string())
}

/// Wrap raw OpenPGP data in ASCII armor.
///
/// Takes raw binary OpenPGP data and an `ArmorKind` specifying the armor
/// header type, and returns the ASCII-armored string.
#[pyfunction]
pub fn armor(data: &[u8], kind: ArmorKind) -> PyResult<String> {
    let mut output = vec![];
    {
        let mut writer =
            sequoia_openpgp::armor::Writer::new(&mut output, kind.into()).map_err(runtime_err)?;
        std::io::Write::write_all(&mut writer, data).map_err(runtime_err)?;
        writer.finalize().map_err(runtime_err)?;
    }
    String::from_utf8(output).map_err(runtime_err)
}

#[pymodule]
pub mod pysequoia {
    use pyo3::prelude::*;

    #[pymodule_export]
    pub use super::Decrypted;
    #[pymodule_export]
    pub use super::armor;
    #[pymodule_export]
    pub use super::cert::Cert;
    #[pymodule_export]
    pub use super::cert::Profile;
    #[pymodule_export]
    pub use super::decrypt::PyDecryptor;
    #[pymodule_export]
    pub use super::decrypt::decrypt;
    #[pymodule_export]
    pub use super::decrypt::decrypt_file;
    #[pymodule_export]
    pub use super::encrypt::encrypt;
    #[pymodule_export]
    pub use super::encrypt::encrypt_file;
    #[pymodule_export]
    pub use super::notation::Notation;
    #[pymodule_export]
    pub use super::sign::SignatureMode;
    #[pymodule_export]
    pub use super::sign::sign;
    #[pymodule_export]
    pub use super::sign::sign_file;
    #[pymodule_export]
    pub use super::signature::Sig;
    #[pymodule_export]
    pub use super::signer::PySigner;
    #[pymodule_export]
    pub use super::types::ArmorKind;
    #[pymodule_export]
    pub use super::user_id::UserId;
    #[pymodule_export]
    pub use super::verify::verify;

    #[pymodule]
    pub mod packet {
        #[pymodule_export]
        pub use crate::packet::PacketPile;
        #[pymodule_export]
        pub use crate::packet::PyPacket;
        #[pymodule_export]
        pub use crate::types::DataFormat;
        #[pymodule_export]
        pub use crate::types::HashAlgorithm;
        #[pymodule_export]
        pub use crate::types::KeyFlags;
        #[pymodule_export]
        pub use crate::types::PublicKeyAlgorithm;
        #[pymodule_export]
        pub use crate::types::SignatureType;
        #[pymodule_export]
        pub use crate::types::Tag;
    }
}
