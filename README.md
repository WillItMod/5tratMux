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

OS updates that include a native MUX bundle install MUX from those local files.
The updater verifies the signed manifest and archive checksum before replacing
the running application, and restores the previous container if its health check
fails. This bundled installation needs no additional release download or DNS
lookup after the OS package arrives. Existing settings and saved DNS choices
are preserved.

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
state, installation identity and licence data. When power is On, it performs a
health check and restores the previous container if startup fails. When power
is Off, it creates the verified image as a stopped container with automatic
restart disabled, without temporarily starting Mux or probing its HTTP service.
Updates, rollback and failure recovery preserve that saved Off choice; a stop
or verification failure remains an error. OS handoffs receive a separate,
operation-bound result that later bootstrap or watchdog checks cannot overwrite.

Installing or updating 5tratMux does not start the trial. An eligible
168-hour preview starts only after the user explicitly selects
**Start 168-hour preview** inside Mux. When that preview ends, another can
become available after the current 90-day cooldown. The cooldown does not
start a trial automatically.

Useful commands:

```bash
sudo /usr/local/sbin/5tratmux-update --status
sudo /usr/local/sbin/5tratmux-update --check
sudo /usr/local/sbin/5tratmux-update --install
sudo /usr/local/sbin/5tratmux-update --rollback
```

## Connecting a new miner

Before connecting, power Mux on, check active access in **System**, and make
sure **Pools** has an enabled, healthy destination for the miner's algorithm.

1. In **Setup**, select **Scan local network**, or enter the miner's IP and
   select **Check this miner**. This reads supported management APIs; finding
   a miner does not change its pool settings. An empty scan does not prevent
   manual connection.
2. If automatic configuration is supported, select **Review before changing**,
   check the details, then confirm **Route through 5tratMux**. Otherwise open
   the miner's own pool settings and copy the pool URL, username/worker and
   password from Mux's **Manual connection** card. Save the settings and let
   the miner reconnect; restart its mining service if the firmware requires it.
   Preserve existing pools as fallbacks.
3. A successful connection adds the worker to **Miners** automatically. Select
   its card, choose compatible pools totalling **100%**, and select
   **Apply allocation**. Look for a live route and increasing accepted shares.
   **ADD** selects an existing miner for a shared allocation; it does not
   register a new miner or enable AI.
4. For optional automation, open **AI Automation**, configure your provider,
   select this miner and its allowed chains in the desired mode, then select
   **Enable mode** or **Update mode**. An existing mode does not automatically
   add a newly connected miner to its selection.

Use the Mux box's LAN address as the pool host, not the miner's IP or
`localhost`. The default endpoint is `stratum+tcp://MUX_LAN_IP:7331`; copy the
displayed values if the installation uses a different port. Give each miner a
unique username/worker, such as `S19J-Garage`. `MyMiner` is a valid SHA256
example, not a required name. Manual Scrypt connections use
`scrypt.YOUR_WORKER` on the same port. Payout settings stay in the destination
pool application.

Discovery, hardware hashrate and a ping reply do not prove that work reaches a
pool through Mux. A live route and accepted shares provide that evidence.
Local AI can remain off when using manual routing or another AI provider.

## Licence backup and PC replacement

With 5tratMux 0.9.52, save your licence-proof JSON from **System → Licensing**.
After reinstalling 5tratumOS or moving to another PC, upload that proof in the
same screen and confirm **Move licence to this PC**. The 5tratumOS Settings
licence shortcut opens this screen directly on OS versions that include it.

Each paid licence supports **five self-service moves in total**. A move keeps
the original plan and expiry; it does not start a fresh annual term. Repeating
the same restore on the already-bound installation does not consume a move.
An older valid backup can still be used within the same five-move allowance.
The interface shows how many moves remain, and the current proof can be
downloaded again after refreshing the browser.

Restoration requires an internet connection. The authority retires the old
binding when it activates the replacement. An online old installation loses
paid access at its next successful licensing check; an offline installation
can retain access until its previously signed offline lease/grace expires.
Keep the proof private: it contains a recovery secret. Contact support if the
proof is missing or the self-service allowance is exhausted.

## Optional Local AI

With 5tratumOS 0.8.4, compatible Linux AMD64 hosts can install the managed Local
5TRATMUX provider from AI Automation. An active paid licence is required;
trials cannot download or run local models. Choose Qwen3.5 0.8B, 2B or 4B:
only the selected model is downloaded, with pinned source and integrity checks.
CPU features (including AVX2), available RAM and disk space are checked before
use. ARM local inference is not qualified by this release.

Native 0.9.49 restores MUX Attack monitoring and app-validated local launches for
this provider. Saved evidence thresholds and paid-access checks still apply;
selecting Local AI does not authorize arbitrary model-generated launch plans.

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

## Block metrics in 0.9.53

Recorded hashrates are now shown consistently, and exact submission evidence
survives restarts. Blockchain-only payout matches remain clearly distinguished
from miner-attributed blocks. See [the release notes](release/notes/v0.9.53.md).

## Local AI recovery in 0.9.54

Local AI research now survives a failed address when DNS supplies another safe
route, preventing one dead IPv6 or CDN endpoint from putting every tracked coin
into Hold-Route. The Local AI panel also supports signed in-place runtime
updates and explicit model switching without deleting downloaded models or
forgetting the previous On/Off state. See
[the release notes](release/notes/v0.9.54.md).

## Miner discovery and connection guidance in 0.9.55

Recognised CGMiner-compatible devices now appear in discovery with manual
connection instructions when automatic configuration is unsupported. A
restricted pool-settings read no longer hides an otherwise identified miner.
Earlier local authorization responses improve compatibility with miners that
have short handshake deadlines, while upstream authorization remains required
before mining work is forwarded. Setup and routing screens now explain the
connection steps and distinguish an absent session from an active route. See
[the release notes](release/notes/v0.9.55.md).
