use pyo3::prelude::*;
use sequoia_openpgp::{cert::prelude::ValidComponentAmalgamation, packet::UserID};

use crate::notation::Notation;

#[pyclass]
pub struct UserId {
    value: String,
    notations: Vec<Notation>,
}

impl UserId {
    pub fn new(user: ValidComponentAmalgamation<UserID>) -> PyResult<Self> {
        let signature = user.binding_signature();
        Ok(Self {
            value: String::from_utf8_lossy(user.component().value()).into(),
            notations: signature
                .notation_data()
                .filter(|n| n.flags().human_readable())
                .map(Notation::from)
                .collect(),
        })
    }
}

#[pymethods]
impl UserId {
    pub fn __str__(&self) -> &str {
        &self.value
    }

    fn __repr__(&self) -> String {
        format!("<UserId value='{}'>", self.value)
    }

    #[getter]
    fn notations(&self) -> Vec<Notation> {
        self.notations.clone()
    }
}
