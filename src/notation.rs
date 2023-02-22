use openpgp::packet::signature::subpacket::NotationData;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

#[pyclass]
#[derive(Clone)]
pub struct Notation {
    key: String,
    value: String,
}

impl Notation {
    pub fn new(notation: &NotationData) -> Self {
        Self {
            key: notation.name().into(),
            value: String::from_utf8_lossy(notation.value()).into(),
        }
    }
}

#[pymethods]
impl Notation {
    #[getter]
    pub fn key(&self) -> &String {
        &self.key
    }

    #[getter]
    pub fn value(&self) -> &String {
        &self.value
    }

    fn __repr__(&self) -> String {
        format!("<Notation key={} value='{}'>", self.key, self.value)
    }
}
