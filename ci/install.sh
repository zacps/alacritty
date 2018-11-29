#!/bin/bash

# Add clippy for linting with nightly builds
if [ "$TRAVIS_RUST_VERSION" == "nightly" ]; then
    rustup component add clippy-preview
fi

if [ "$TRAVIS_OS_NAME" == "windows" ]; then
    choco install 7zip.portable
fi