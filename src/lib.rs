use std::borrow::Cow;

mod cert;
mod decrypt;
mod encrypt;
mod notation;
mod sign;
mod signature;
mod signer;
mod user_id;
mod verify;

use pyo3::prelude::*;
use sequoia_openpgp::armor::Kind;
use sequoia_openpgp::packet::Packet;
use sequoia_openpgp::parse::stream::GoodChecksum;
use sequoia_openpgp::serialize::stream::Armorer;
use sequoia_openpgp::serialize::{stream::Message, Marshal};

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
    #[getter]
    fn certificate(&self) -> &str {
        &self.certificate
    }

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

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct Decrypted {
    valid_sigs: Vec<ValidSig>,
    content: Option<Vec<u8>>,
}

#[pymethods]
impl Decrypted {
    #[getter]
    pub fn bytes(&self) -> Option<Cow<'_, [u8]>> {
        self.content
            .as_ref()
            .map(|content| Cow::Borrowed(&content[..]))
    }

    #[getter]
    pub fn valid_sigs(&self) -> Vec<ValidSig> {
        self.valid_sigs.clone()
    }
}

#[pymodule]
pub mod pysequoia {
    #[pymodule_export]
    pub use super::cert::Cert;
    #[pymodule_export]
    pub use super::cert::Profile;
    #[pymodule_export]
    pub use super::decrypt::decrypt;
    #[pymodule_export]
    pub use super::decrypt::decrypt_file;
    #[pymodule_export]
    pub use super::decrypt::PyDecryptor;
    #[pymodule_export]
    pub use super::encrypt::encrypt;
    #[pymodule_export]
    pub use super::encrypt::encrypt_file;
    #[pymodule_export]
    pub use super::notation::Notation;
    #[pymodule_export]
    pub use super::sign::sign;
    #[pymodule_export]
    pub use super::sign::sign_file;
    #[pymodule_export]
    pub use super::sign::SignatureMode;
    #[pymodule_export]
    pub use super::signature::Sig;
    #[pymodule_export]
    pub use super::signer::PySigner;
    #[pymodule_export]
    pub use super::user_id::UserId;
    #[pymodule_export]
    pub use super::verify::verify;
    #[pymodule_export]
    pub use super::Decrypted;
}
