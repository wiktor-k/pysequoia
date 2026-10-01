use pyo3::prelude::*;
use sequoia_openpgp::policy::{
    HashAlgoSecurity as SqHashSecurity, StandardPolicy as SqStandardPolicy,
};

use crate::types::HashAlgorithm;

/// A cryptographic security property required by a signature.
#[pyclass(eq, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashSecurity {
    /// Resistance to finding two messages with the same hash.
    CollisionResistance,
    /// Resistance to finding another message with a matching hash.
    SecondPreImageResistance,
}

impl From<HashSecurity> for SqHashSecurity {
    fn from(security: HashSecurity) -> Self {
        match security {
            HashSecurity::CollisionResistance => Self::CollisionResistance,
            HashSecurity::SecondPreImageResistance => Self::SecondPreImageResistance,
        }
    }
}

/// The standard OpenPGP cryptographic policy.
///
/// A new policy uses Sequoia's secure defaults. Pass it to `verify`, `decrypt`,
/// or `decrypt_file` after making any required compatibility adjustments.
#[pyclass]
pub struct StandardPolicy {
    inner: SqStandardPolicy<'static>,
}

impl Default for StandardPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardPolicy {
    pub fn inner(&self) -> &SqStandardPolicy<'static> {
        &self.inner
    }
}

#[pymethods]
impl StandardPolicy {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: SqStandardPolicy::new(),
        }
    }

    /// Accept a hash algorithm for all signature security contexts.
    ///
    /// This weakens the policy for algorithms that are no longer considered
    /// cryptographically secure. In particular, SHA-1 lacks collision resistance.
    pub fn accept_hash(&mut self, algorithm: HashAlgorithm) {
        self.inner.accept_hash(algorithm.into());
    }

    /// Accept a hash algorithm only where the specified security property is required.
    ///
    /// This is less permissive than `accept_hash`. For example, accepting SHA-1 for
    /// second-preimage resistance does not allow it for data signatures, which also
    /// require collision resistance.
    pub fn accept_hash_property(&mut self, algorithm: HashAlgorithm, security: HashSecurity) {
        self.inner
            .accept_hash_property(algorithm.into(), security.into());
    }
}
