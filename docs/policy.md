# Cryptographic policies

PySequoia uses the build's default cryptographic policy when reading or using
certificates, verifying signatures, or decrypting messages. To use a different
policy, load one from a Sequoia configuration file and pass it to the operation.
For example, a configuration file can permit legacy SHA-1 certificate signatures
without permitting SHA-1 data signatures:

```toml
[hash_algorithms]
sha1.second_preimage_resistance = "always"
```

```python
from pysequoia import Policy, verify

policy = Policy.from_sequoia_config_file("/path/to/policy.toml")
result = verify(signed, get_certs_verify, policy=policy)
```

The policy can also be passed to certificate and secret key readers, such as
`Cert.from_file` and `Tsk.from_file`, and to `decrypt` and `decrypt_file`.
`repr(policy)` shows the configuration path or indicates that the policy uses
the build's default.

## Using a system policy configuration

To use a Sequoia policy managed by the operating system, omit the path:

```python
policy = Policy.from_sequoia_config_file()
result = verify(signed, get_certs_verify, policy=policy)
```

With no path, `from_sequoia_config_file` reads the absolute path in
`SEQUOIA_CRYPTO_POLICY` when that variable is set. Otherwise, it reads
`/etc/crypto-policies/back-ends/sequoia.config`.

This default path is a Sequoia convention, not a guarantee across Linux
distributions. Check that supported distributions provide a config there before
relying on it.

Setting `SEQUOIA_CRYPTO_POLICY` to an empty string explicitly selects
the built-in default policy. A missing or invalid file raises an exception
instead of falling back to the default policy.

Distributions can build with the Cargo feature `system-policy-default` to use
the system policy by default for operations where no policy is passed. The
configuration is loaded at import time. If the file is missing or invalid,
the import fails. Ensure `/etc/crypto-policies/back-ends/sequoia.config` exists
or set `SEQUOIA_CRYPTO_POLICY` to another absolute path. Explicitly passed
policies still override the default.

The feature selects a Sequoia policy; it does not change the cryptographic
backend or load OpenSSL configuration.

For the security properties and other advanced policy controls, see Sequoia's
[policy documentation][policy-docs] and its
[policy configuration format][policy-config].

[policy-docs]: https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/policy/index.html
[policy-config]: https://docs.rs/sequoia-policy-config/latest/sequoia_policy_config/
