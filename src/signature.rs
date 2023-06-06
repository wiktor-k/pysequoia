use std::borrow::Cow;

use openpgp::packet::Signature as SqSignature;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

#[pyclass]
pub struct Signature {
    sig: SqSignature,
}

impl Signature {
    pub fn new(sig: SqSignature) -> Self {
        Self { sig }
    }
}

impl From<SqSignature> for Signature {
    fn from(sig: SqSignature) -> Self {
        Self { sig }
    }
}

#[pymethods]
impl Signature {
    pub fn bytes(&self) -> PyResult<Cow<[u8]>> {
        Ok(crate::serialize(self.sig.clone().into(), None)?.into())
    }

    pub fn __str__(&self) -> PyResult<String> {
        let bytes = crate::serialize(self.sig.clone().into(), openpgp::armor::Kind::Signature)?;
        Ok(String::from_utf8(bytes)?)
    }
}
