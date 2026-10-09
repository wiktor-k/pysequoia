use std::path::PathBuf;

use anyhow::anyhow;
use pyo3::prelude::*;
use sequoia_openpgp::policy::{
    HashAlgoSecurity as SqHashSecurity, StandardPolicy as SqStandardPolicy,
};
use sequoia_policy_config::ConfiguredStandardPolicy;

use crate::types::HashAlgorithm;

/// A cryptographic security property required by a signature.
#[pyclass(eq, from_py_object)]
#[derive(Clone, PartialEq, Eq)]
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

/// An OpenPGP cryptographic policy.
///
/// Create a policy using `Policy.standard()`, then pass it to `verify`, `decrypt`,
/// or `decrypt_file` after making any required compatibility adjustments.
#[pyclass]
pub struct Policy {
    inner: SqStandardPolicy<'static>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::standard()
    }
}

impl Policy {
    pub fn inner(&self) -> &SqStandardPolicy<'static> {
        &self.inner
    }

    fn from_configured_policy(policy: ConfiguredStandardPolicy<'static>) -> Self {
        Self {
            inner: policy.build(),
        }
    }
}

#[pymethods]
impl Policy {
    /// Create a policy with Sequoia's secure standard defaults.
    #[staticmethod]
    pub fn standard() -> Self {
        Self {
            inner: SqStandardPolicy::new(),
        }
    }

    /// Load a policy from a Sequoia policy configuration file.
    ///
    /// The file uses Sequoia's TOML policy format. Missing or invalid files
    /// raise an exception.
    #[staticmethod]
    pub fn from_config_file(path: PathBuf) -> PyResult<Self> {
        let mut policy = ConfiguredStandardPolicy::new();
        if !policy.parse_config_file(&path)? {
            return Err(anyhow!("Policy configuration file not found: {}", path.display()).into());
        }
        Ok(Self::from_configured_policy(policy))
    }

    /// Load the system's Sequoia policy configuration.
    ///
    /// This explicitly checks `SEQUOIA_CRYPTO_POLICY` first, then
    /// `/etc/crypto-policies/back-ends/sequoia.config`. Missing or invalid
    /// configuration raises an exception; policies are never loaded automatically.
    #[staticmethod]
    pub fn from_system_config() -> PyResult<Self> {
        let mut policy = ConfiguredStandardPolicy::new();
        if !policy.parse_default_config()? {
            return Err(anyhow!("System Sequoia policy configuration not found").into());
        }
        Ok(Self::from_configured_policy(policy))
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
