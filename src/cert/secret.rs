use openpgp::serialize::SerializeInto;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

#[pyclass]
pub struct SecretCert {
    cert: openpgp::cert::Cert,
}

impl SecretCert {
    pub fn new(cert: openpgp::cert::Cert) -> Self {
        Self { cert }
    }
}

#[pymethods]
impl SecretCert {
    pub fn __str__(&self) -> PyResult<String> {
        let armored = self.cert.as_tsk().armored();
        Ok(String::from_utf8(armored.to_vec()?)?)
    }
}
