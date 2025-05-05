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

#[pyclass]
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

#[pyclass]
#[derive(Clone)]
pub struct Decrypted {
    valid_sigs: Vec<ValidSig>,
    content: Option<Vec<u8>>,
}

#[pymethods]
impl Decrypted {
    #[getter]
    pub fn bytes(&self) -> Option<Cow<[u8]>> {
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
fn pysequoia(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<cert::Cert>()?;
    m.add_class::<signature::Sig>()?;
    m.add_class::<notation::Notation>()?;
    m.add_class::<sign::SignatureMode>()?;
    m.add_function(wrap_pyfunction!(sign::sign, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt::encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt::decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(verify::verify, m)?)?;
    Ok(())
}
