#!/bin/bash
set -euo pipefail

# publish order
CRATES=(
    "pingap-util"
    "pingap-core"
    "pingap-discovery"
    "pingap-config"
    "pingap-logger"
    "pingap-certificate"
    "pingap-cache"
    "pingap-location"
    "pingap-health"
    "pingap-upstream"
    "pingap-acme"
    "pingap-otel"
    "pingap-performance"
    "pingap-plugin"
    "pingap-pyroscope"
    "pingap-sentry"
    "pingap-webhook"
    "pingap-proxy"
    "pingap-imageoptim"
)

for crate in "${CRATES[@]}"; do
    echo "Publishing $crate..."
    # A subshell keeps the working directory correct even when a publish
    # fails; with `set -e` the script stops at the first failure instead of
    # continuing from the wrong directory.
    (cd "$crate" && cargo publish --registry crates-io)
    # wait for crates.io to process
    sleep 60
done

echo "All crates published successfully!"
