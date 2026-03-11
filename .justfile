#!/usr/bin/env -S just --working-directory . --justfile

clippy := "cargo clippy --quiet --workspace --no-deps --all-targets"
clippy_args := "-D warnings"
nextest_args := "--locked --workspace"
udeps_args := "--quiet --workspace --all-features --all-targets"

# Perform all checks
[parallel]
check: spell fmt doc lints deps unused-deps recipes test integration-test

# Check spelling
[group('ci')]
[metadata('pacman', 'codespell')]
spell:
    codespell

# Check source code formatting
[group('ci')]
[metadata('pacman', 'rustup')]
fmt:
    just --unstable --fmt --check
    # We're using nightly to properly group imports, see .rustfmt.toml
    rustup component add --toolchain nightly rustfmt
    cargo +nightly fmt --quiet --all -- --check

# Lint the source code
[group('ci')]
[metadata('gitlabci-job', '{"artifacts":{"when":"always","paths":["target/clippy"]}}')]
[metadata('pacman', 'rust', 'python')]
lints:
    #!/usr/bin/bash
    set -euo pipefail

    if [ "${CI:-}" = "true" ]; then
        ARGS=(--message-format=json)
    else
        ARGS=()
    fi

    mkdir -p target
    {{ clippy }} "${ARGS[@]}" -- {{ clippy_args }} | tee target/clippy

# Create lints report
[metadata('gitlabci-job', '{"stage":"deploy","when":"always","artifacts":{"reports":{"codequality":"target/codeclimate.json"}}}')]
[metadata('pacman', 'cargo-sonar', 'rust')]
create-codeclimate:
    # deny reports can be tested by adding a yanked dep e.g. `cargo add ed25519-dalek@0.9.0`
    cargo codeclimate \
        --clippy --clippy-path "target/clippy" \
        --deny --deny-path "target/deny" \
        --udeps --udeps-path "target/udeps" \
        --codeclimate-path target/codeclimate.json

# Check for issues with dependencies
[group('ci')]
[metadata('gitlabci-job', '{"artifacts":{"when":"always","paths":["target/deny"]}}')]
[metadata('pacman', 'cargo-deny')]
deps:
    #!/usr/bin/bash
    set -euo pipefail

    if [ "${CI:-}" = "true" ]; then
        ARGS=(--format json)
    else
        ARGS=()
    fi

    mkdir -p target
    cargo deny "${ARGS[@]}" check -D advisory-not-detected -D license-not-encountered -D no-license-field 2>&1 | tee target/deny

# Check for unused dependencies
[group('ci')]
[metadata('gitlabci-job', '{"artifacts":{"when":"always","paths":["target/udeps"]}}')]
[metadata('pacman', 'cargo-machete', 'cargo-udeps', 'rust', 'python')]
unused-deps:
    #!/usr/bin/bash
    set -euo pipefail

    if [ "${CI:-}" = "true" ]; then
        ARGS=(--output json)
    else
        ARGS=()
    fi

    mkdir -p target
    cargo +nightly udeps {{ udeps_args }} "${ARGS[@]}" | tee target/udeps
    cargo +nightly machete

# Run unit tests
[metadata('pacman', 'cargo-nextest')]
test:
    #!/usr/bin/bash
    set -euxo pipefail

    if [ "${CI:-}" = "true" ]; then
        PROFILE=ci
    else
        PROFILE=default
    fi

    cargo +nightly nextest run {{ nextest_args }} --profile "$PROFILE"
    cargo +nightly nextest run --no-default-features {{ nextest_args }} --profile "$PROFILE"

# Run integration tests
[metadata('pacman', 'git', 'jq', 'openssh', 'tangler', 'tree')]
integration-test:
    #!/usr/bin/bash
    set -euo pipefail
    cargo +nightly build --locked
    target=$(cargo +nightly metadata --format-version 1 | jq --raw-output '.target_directory')
    tangler sh < README.md | sed --quiet --regexp-extended 's/^\$ (.*)/\1/p' | PATH="$target/debug:$PATH" bash -euxo pipefail -

# Report on all tests
[group('ci')]
[metadata('gitlabci-job', '{"coverage":"/Line coverage: ([0-9.]*)%/","artifacts":{"when":"always","reports":{"junit":"target/nextest/ci/junit.xml","metrics":"target/metrics.txt","coverage_report":{"coverage_format":"cobertura","path":"target/coverage.xml"}}}}')]
[metadata('pacman', 'rust', 'cargo-llvm-cov', 'rustup', 'python')]
report-test:
    #!/usr/bin/bash
    # enabling "x" here will garble text output that's parsed by GitLab for code coverage
    set -euo pipefail

    rustup component add --toolchain nightly llvm-tools-preview

    # shellcheck disable=SC1090
    source <(cargo +nightly llvm-cov show-env --export-prefix --doctests --branch)
    cargo +nightly llvm-cov clean

    just test integration-test

    # explicitly use "target" (even if CARGO_TARGET_DIR is somewhere else) so that
    # local tools (such as https://github.com/ryanluker/vscode-coverage-gutters) can find the file
    cargo +nightly llvm-cov --quiet report --cobertura --output-path target/coverage.xml > /dev/null 2>&1

    LINE_RATE=$(head target/coverage.xml | sed -nE 's/(.*coverage.*line-rate=")([^"]*)".*/\2/p')
    LINE_PERCENT=$(echo "$LINE_RATE" | awk '{print $1 * 100}')
    printf 'Line coverage: %s%%\n' "$LINE_PERCENT"

    BRANCH_RATE=$(head target/coverage.xml | sed -nE 's/(.*coverage.*branch-rate=")([^"]*)".*/\2/p')
    printf 'line_coverage_ratio %s\nbranch_coverage_ratio %s\n' "$LINE_RATE" "$BRANCH_RATE" > target/metrics.txt

# Generate HTML report for the coverage
coverage-html-report: report-test
    #!/usr/bin/bash
    set -euo pipefail
    # shellcheck disable=SC1090
    source <(cargo +nightly llvm-cov show-env --export-prefix)
    cargo +nightly llvm-cov --quiet report --html > /dev/null 2>&1
    printf "The coverage report is in file://%s/llvm-cov/html/index.html\n" "${CARGO_TARGET_DIR:-target}"

# Build docs
[group('ci')]
[metadata('pacman', 'rust', 'python')]
doc:
    RUSTDOCFLAGS='-D warnings' cargo doc --quiet --no-deps --document-private-items

# Check commit messages
[metadata('pacman', 'codespell', 'git')]
commits:
    #!/usr/bin/env bash
    set -Eeuo pipefail

    # fetch default branch if it is set
    if [[ -v CI_DEFAULT_BRANCH ]]; then
        git fetch origin "$CI_DEFAULT_BRANCH"
        refs="origin/$CI_DEFAULT_BRANCH"
    else
        refs="main"
    fi

    commits=$(git rev-list "${refs}..")
    for commit in $commits; do
      MSG="$(git show -s --format=%B "$commit")"
      CODESPELL_RC="$(mktemp)"
      git show "$commit:.codespellrc" > "$CODESPELL_RC"
      if ! grep -q "Signed-off-by: " <<< "$MSG"; then
        printf "⛔ Commit %s lacks \"Signed-off-by\" line.\n" "$commit"
        printf "%s\n" \
            "  Please use:" \
            "    git rebase --signoff main && git push --force-with-lease" \
            "  See https://developercertificate.org/ for more details."
        exit 1;
      elif ! codespell --config "$CODESPELL_RC" - <<< "$MSG"; then
        printf "⛔ The spelling in commit %s needs improvement.\n" "$commit"
        exit 1;
      elif grep "WIP: " <<< "$MSG"; then
        printf "⛔ Commit %s includes a 'WIP' marker which should be removed.\n" "$commit"
        exit 1;
      else
        printf "✅ Commit %s is good.\n" "$commit"
      fi
    done

# Lint justfile recipes
[group('ci')]
[metadata('pacman', 'nodejs', 'shellcheck')]
recipes:
    #!/usr/bin/env bash
    set -euo pipefail
    T=$(mktemp -d)
    node scripts/ci/export-shell.ts "$T"
    for file in "$T"/*.sh; do
        echo "Checking $file..."
        shellcheck --shell bash "$file"
    done

# Fixes common issues. Files need to be git add'ed
fix:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! git diff-files --quiet ; then
        echo "Working tree has changes. Please stage them: git add ."
        exit 1
    fi

    codespell --write-changes
    just --unstable --fmt
    # try to fix rustc issues
    cargo fix --allow-staged
    # try to fix clippy issues
    cargo clippy --fix --allow-staged

    # fmt must be last as clippy changes may break formatting
    cargo +nightly fmt --all

# Run README integration tests
[group('ci')]
[metadata('pacman', 'rust', 'python', 'tangler')]
readme:
    #!/usr/bin/env bash
    set -euo pipefail

    GNUPGHOME=$(mktemp --directory)
    export GNUPGHOME

    # shellcheck disable=SC1090
    source <(tangler bash < README.md)
    tangler python < README.md | python -

# Update stubs (python/pysequoia/__init__.pyi, python/pysequoia/packet.pyi, ...)
[metadata('pacman', 'rust')]
update-stubs:
    #!/usr/bin/bash
    set -euo pipefail
    cargo build
    LIB=$(find "${CARGO_TARGET_DIR:-target}/debug" -maxdepth 1 \( -name 'libpysequoia.so' -o -name 'libpysequoia.dylib' \) -print -quit)
    find python/pysequoia -name '*.pyi' -delete 2>/dev/null || true
    cargo xtask generate-stubs "$LIB"

# Check types in the README
[metadata('pacman', 'mypy', 'python', 'rust', 'tangler')]
check-types: update-stubs
    tangler python < README.md > README.py
    mypy --config-file pyproject.toml README.py

# Generate stubs and check types
[group('ci')]
update-and-check-types: update-stubs check-types
