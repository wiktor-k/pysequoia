use std::path::PathBuf;
#[cfg(feature = "system-policy-default")]
use std::sync::OnceLock;

use anyhow::anyhow;
use pyo3::prelude::*;
use sequoia_openpgp::policy::StandardPolicy as SqStandardPolicy;
use sequoia_policy_config::ConfiguredStandardPolicy;

#[cfg(feature = "system-policy-default")]
static SYSTEM_DEFAULT: OnceLock<Policy> = OnceLock::new();

pub fn default_policy() -> SqStandardPolicy<'static> {
    #[cfg(feature = "system-policy-default")]
    return SYSTEM_DEFAULT
        .get()
        .expect("system policy must be loaded during module initialization")
        .inner
        .clone();

    #[cfg(not(feature = "system-policy-default"))]
    SqStandardPolicy::new()
}

#[cfg(feature = "system-policy-default")]
pub fn initialize_system_default() -> PyResult<()> {
    let policy = Policy::from_sequoia_config_file(None)?;
    let _ = SYSTEM_DEFAULT.set(policy);
    Ok(())
}

/// An OpenPGP cryptographic policy.
///
/// Pass a policy when reading or using certificates, or to `verify`,
/// `decrypt`, and `decrypt_file`.
#[pyclass]
#[derive(Clone)]
pub struct Policy {
    inner: SqStandardPolicy<'static>,
    source: Option<PathBuf>,
}

impl Default for Policy {
    fn default() -> Self {
        #[cfg(feature = "system-policy-default")]
        return SYSTEM_DEFAULT
            .get()
            .expect("system policy must be loaded during module initialization")
            .clone();

        #[cfg(not(feature = "system-policy-default"))]
        Self {
            inner: default_policy(),
            source: None,
        }
    }
}

impl Policy {
    pub fn inner(&self) -> &SqStandardPolicy<'static> {
        &self.inner
    }

    fn from_configured_policy(
        policy: ConfiguredStandardPolicy<'static>,
        source: Option<PathBuf>,
    ) -> Self {
        Self {
            inner: policy.build(),
            source,
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
        let found = if let Some(path) = path.as_ref() {
            policy.parse_config_file(path)?
        } else {
            policy.parse_default_config()?
        };
        if !found {
            return Err(anyhow!("Sequoia policy configuration file not found").into());
        }
        let source = path.or_else(|| {
            std::env::var_os(ConfiguredStandardPolicy::ENV_VAR)
                .map(PathBuf::from)
                .or_else(|| Some(PathBuf::from(ConfiguredStandardPolicy::CONFIG_FILE)))
        });
        let source = source.filter(|path| !path.as_os_str().is_empty());
        Ok(Self::from_configured_policy(policy, source))
    }

    fn __repr__(&self) -> String {
        match &self.source {
            Some(path) => format!("<Policy config={path:?}>"),
            None => "<Policy default>".to_string(),
        }
    }
}
