use pyo3::prelude::*;
use sequoia_openpgp::packet::signature::subpacket::NotationData;

/// A key-value notation attached to an OpenPGP signature.
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct Notation {
    key: String,
    value: String,
}

impl From<&NotationData> for Notation {
    fn from(notation: &NotationData) -> Self {
        Self {
            key: notation.name().into(),
            value: String::from_utf8_lossy(notation.value()).into(),
        }
    }
}

#[pymethods]
impl Notation {
    /// Create a new notation with the given key and value.
    #[new]
    pub fn new(key: String, value: String) -> Self {
        Self { key, value }
    }

    /// The notation key (name).
    #[getter]
    pub fn key(&self) -> &String {
        &self.key
    }

    /// The notation value.
    #[getter]
    pub fn value(&self) -> &String {
        &self.value
    }

    fn __str__(&self) -> String {
        format!("{}={}", self.key, self.value)
    }

    fn __repr__(&self) -> String {
        format!("<Notation key={} value='{}'>", self.key, self.value)
    }
}
