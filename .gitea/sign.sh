#!/usr/bin/env bash
# Signs dist/SHA256SUMS of the release being built into dist/SHA256SUMS.sig: ed25519 over
# "dvpn-release\n<owner/repo>\n<tag>\n" + SHA256SUMS, what dvpn-installer checks before it installs
# anything (DVPN-installer/src/release.rs). Needs RELEASE_SIGNING_KEY (the PEM private key, an
# organization secret) and GITHUB_REPOSITORY, GITHUB_REF_NAME (set by Gitea Actions).
# The same file is in DVPN, DVPN-tui, DVPN-gui and DVPN-installer.
set -euo pipefail

: "${RELEASE_SIGNING_KEY:?no RELEASE_SIGNING_KEY secret: releases must be signed for dvpn-installer}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "$RELEASE_SIGNING_KEY" >"$tmp/key.pem"
{
	printf 'dvpn-release\n%s\n%s\n' "$GITHUB_REPOSITORY" "$GITHUB_REF_NAME"
	cat dist/SHA256SUMS
} >"$tmp/msg"
openssl pkeyutl -sign -inkey "$tmp/key.pem" -rawin -in "$tmp/msg" -out dist/SHA256SUMS.sig
openssl pkey -in "$tmp/key.pem" -pubout -out "$tmp/pub.pem"
openssl pkeyutl -verify -pubin -inkey "$tmp/pub.pem" -rawin -in "$tmp/msg" -sigfile dist/SHA256SUMS.sig
pub=$(openssl pkey -in "$tmp/key.pem" -pubout -outform DER | tail -c 32 | od -An -tx1 -v | tr -d ' \n')
echo "signed by $pub"
# RELEASE_PUBLIC_KEY (what the installer is built with) must hold the key that signs
if [[ -n ${RELEASE_PUBLIC_KEY:-} ]] && ! tr ', ' '\n\n' <<<"$RELEASE_PUBLIC_KEY" | grep -qx "$pub"; then
	echo "RELEASE_SIGNING_KEY is not one of RELEASE_PUBLIC_KEY: the installer would refuse this release"
	exit 1
fi
