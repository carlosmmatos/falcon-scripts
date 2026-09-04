#!/bin/sh

# Installs the packages that .github/scripts/test-curl-oauth-live.sh needs:
# curl and a python interpreter. Only missing packages are installed, so the
# script does nothing on images that already have both. RHEL/CentOS 7 images
# supply curl and python2 already, so no package manager runs there.

set -eu

have() {
    command -v "$1" >/dev/null 2>&1
}

have_python() {
    have python3 || have python2 || have python
}

if have curl && have_python; then
    echo 'curl and python are already present; no packages to install.'
    exit 0
fi

if have apk; then
    packages=""
    have curl || packages="$packages curl"
    have_python || packages="$packages python3"
    # shellcheck disable=SC2086  # deliberate word splitting into package names
    apk add --no-cache $packages
elif have dnf; then
    packages=""
    have curl || packages="$packages curl"
    have_python || packages="$packages python3"
    # shellcheck disable=SC2086  # deliberate word splitting into package names
    dnf install -y -q $packages
elif have yum; then
    packages=""
    have curl || packages="$packages curl"
    have_python || packages="$packages python"
    # shellcheck disable=SC2086  # deliberate word splitting into package names
    yum install -y -q $packages
elif have apt-get; then
    packages=""
    have curl || packages="$packages curl"
    have_python || packages="$packages python3"
    apt-get update -qq
    # shellcheck disable=SC2086  # deliberate word splitting into package names
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $packages
else
    echo 'ERROR: no supported package manager found (apk, dnf, yum, apt-get).' >&2
    exit 1
fi

echo 'Test dependencies are installed.'
