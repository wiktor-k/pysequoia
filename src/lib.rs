use std::borrow::Cow;

use openpgp::parse::stream::GoodChecksum;
use openpgp::serialize::stream::Armorer;
use pyo3::prelude::*;

mod cert;
mod decrypt;
mod encrypt;
mod notation;
mod sign;
mod signature;
mod signer;
mod user_id;
mod verify;

use openpgp::armor::Kind;
use openpgp::packet::Packet;
use openpgp::serialize::{stream::Message, Marshal};
use sequoia_openpgp as openpgp;

pub(crate) fn serialize<T>(p: Packet, armor_kind: T) -> openpgp::Result<Vec<u8>>
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
            signing_key: format!("{:x}", value.ka.fingerprint()),
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
    content: Vec<u8>,
}

#[pymethods]
impl Decrypted {
    #[getter]
    pub fn bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(&self.content)
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
    m.add_function(wrap_pyfunction!(sign::sign, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt::encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt::decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(verify::verify, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use openpgp::cert::prelude::*;
    use sequoia_openpgp as openpgp;
    use sequoia_openpgp::serialize::SerializeInto;
    use testresult::TestResult;

    #[test]
    fn test_armoring() -> TestResult {
        let cert = CertBuilder::general_purpose(None, Some("test@example.com"))
            .generate()?
            .0;
        assert!(cert.armored().to_vec().is_ok());
        Ok(())
    }
}
