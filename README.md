# 5tratMux

5tratMux is the native multi-chain hash router for 5tratumOS. One stable miner
endpoint can keep compatible installed pool applications warm and divide
complete mining jobs between them without repeatedly reconfiguring the miner.

This repository is deliberately release-only. It contains:

- the public installer and updater;
- the Ed25519 public key used to verify release manifests;
- release notes and deployment documentation;
- checksums and signed metadata attached to public releases.

It does **not** contain the private routing, licensing or AI implementation.
Release containers carry a native compiled runtime and minified browser assets.

## Installation and updates

5tratMux is bundled into supported 5tratumOS releases. Its own signed updater
allows later Mux releases to be installed without waiting for a complete OS
update:

```bash
curl -fsSLo /tmp/5tratmux-update \
  https://raw.githubusercontent.com/WillItMod/5tratMux/main/5tratmux-update
chmod +x /tmp/5tratmux-update
sudo /tmp/5tratmux-update --check
sudo /tmp/5tratmux-update --install
```

The updater verifies the signed release manifest and the SHA-256 digest of the
architecture-specific OCI archive before Docker loads it. It preserves local
state, installation identity and licence data, performs a health check, and
automatically restores the previous image if startup fails.

Installing or updating 5tratMux does not start the trial. The recurring
48-hour early-adopter preview starts only after the user explicitly selects
**Start my 48-hour preview** inside Mux.

Useful commands:

```bash
sudo /usr/local/sbin/5tratmux-update --status
sudo /usr/local/sbin/5tratmux-update --check
sudo /usr/local/sbin/5tratmux-update --install
sudo /usr/local/sbin/5tratmux-update --rollback
```

## Public ports

- Web control: `21222/tcp` on the 5tratumOS host
- Miner endpoint: `7331/tcp` on the 5tratumOS host

Wallet keys are never given to 5tratMux. Each installed pool application keeps
control of its own payout wallet and block construction.

## Release security

- Release metadata is signed with Ed25519.
- The updater pins the repository public key in
  `release/update-signing-public.pem`.
- OCI archives are selected by CPU architecture and checked by SHA-256.
- The running container uses no additional Linux capabilities and has
  `no-new-privileges` enabled.
- Licence decisions are signed separately by the 5tratMux authority and bound
  to the 5tratumOS installation identity.

The public release-signing key fingerprint is:

`SHA-256 1d5901e7c64046d15fcdee8c0b1c962d6f946d4a620d2be2765fbb23c0673ddf`
