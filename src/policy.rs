use std::path::PathBuf;

use anyhow::anyhow;
use pyo3::prelude::*;
use sequoia_openpgp::policy::StandardPolicy as SqStandardPolicy;
use sequoia_policy_config::ConfiguredStandardPolicy;

pub fn default_policy() -> SqStandardPolicy<'static> {
    SqStandardPolicy::new()
}

/// An OpenPGP cryptographic policy.
///
/// Pass a policy to `verify`, `decrypt`, or `decrypt_file`.
#[pyclass]
pub struct Policy {
    inner: SqStandardPolicy<'static>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            inner: default_policy(),
        }
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
    /// Create the build's default cryptographic policy.
    #[staticmethod]
    #[expect(
        clippy::should_implement_trait,
        reason = "We want this function exposed to Python"
    )]
    pub fn default() -> Self {
        Default::default()
    }

    /// Load a Sequoia policy configuration file.
    ///
    /// If no path is provided, check the `SEQUOIA_CRYPTO_POLICY` environment variable
    /// and then the system's Sequoia policy file. Missing or invalid configuration raises
    /// an exception.
    #[staticmethod]
    #[pyo3(signature = (path=None))]
    pub fn from_sequoia_config_file(path: Option<PathBuf>) -> PyResult<Self> {
        let mut policy = ConfiguredStandardPolicy::new();
        let found = if let Some(path) = path {
            policy.parse_config_file(&path)?
        } else {
            policy.parse_default_config()?
        };
        if !found {
            return Err(anyhow!("Sequoia policy configuration file not found").into());
        }
        Ok(Self::from_configured_policy(policy))
    }
}
