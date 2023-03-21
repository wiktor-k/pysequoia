#!/bin/bash

set -euxo pipefail

curl --fail -i -d body="Build \`$1\` has status: ${CI_JOB_STATUS}." -H "Authorization: token $CODEBERG_TOKEN" "https://codeberg.org/api/v1/repos/$CI_REPO/issues/$CI_COMMIT_PULL_REQUEST/comments"
