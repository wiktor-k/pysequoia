#!/bin/bash

# Link to that file to do quick checks before each commit:
# $ ln -f -s ../../ci/quick-checks.sh .git/hooks/pre-commit

set -euxo pipefail

cargo fmt -- --check
cargo clippy --all
cargo test --all
