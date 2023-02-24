use openpgp::{cert::prelude::ValidComponentAmalgamation, packet::UserID};
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::notation::Notation;

#[pyclass]
pub struct UserId {
    value: String,
    notations: Vec<Notation>,
}

impl UserId {
    pub fn new(user: ValidComponentAmalgamation<UserID>) -> Self {
        // The component is Valid and as such needs to have at least
        // one self signature. The first one will be the most recent.
        let last_signature = user.self_signatures().next().unwrap();
        Self {
            value: String::from_utf8_lossy(user.value()).into(),
            notations: last_signature
                .notation_data()
                .filter(|n| n.flags().human_readable())
                .map(Notation::from)
                .collect(),
        }
    }
}

#[pymethods]
impl UserId {
    fn __str__(&self) -> &String {
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
