# AusKal unified static-analysis dashboard

Live deployment: **https://dev.auskal.tech**. Existing `godseyeadmin` credentials and HTTPS are preserved. The dashboard is a custom web adapter around open-source engines and REA 6.9.0; it is not an upstream REA product UI.

## Use

1. Sign in with the existing GodsEye account. On first use, explicitly acknowledge that you own the software or have authorization to examine it. This acknowledgment is stored per account, independently of login sessions.
2. Paste a public HTTP(S) URL, drag/drop files, select a source folder, or paste/upload a PNG/JPEG screenshot. Use **Auto-detect** or choose a manual type.
3. Click **Analyze target**. The durable queue shows stage/progress updates while one disposable worker runs at a time.
4. Read the summary, severity counts, review findings, and expandable evidence sections. Download **HTML, PDF, or JSON**, plus available extracted artifacts.

All uploaded input, extracted source, generated files, worker logs, and reports expire after **24 hours**. The supervisor checks expiry every five minutes. Login sessions expire after eight hours and can be revoked with Sign out. Account acknowledgment survives logout. This is a private single-operator workspace, not a multi-tenant authorization system.

### Detection and engine coverage

| Input | Automatic analysis | Important limits |
|---|---|---|
| Public website URL | Bounded GET fetch, response headers/cookie metadata, marker-based technology indicators, Chromium/Playwright render, screenshot, up to 16 client bundles, beautification, safe constant decoding, endpoint references, gitleaks/Semgrep | GET/HEAD only in the renderer; no forms, POST, WebSockets, service workers, media, downloads, login flows, or endpoint probing. Sites may render incompletely. Fingerprints are indicators, not verified product versions. |
| ZIP, TAR, TAR.GZ, project folder | Traversal-safe extraction, file tree, manifest/dependency declarations, gitleaks, local Semgrep rules; REA module evidence for JavaScript projects | No package installation or build scripts. No CVE database lookup. Archives: 5,000 files, 256 MiB expansion, 64 MiB per member, no links/devices/encrypted members. Nested archives are not recursively unpacked. |
| Public HTTPS git URL | Bare shallow clone through the public-only proxy, commit SHA, safe git archive extraction, source pipeline | No checkout hooks, external/file/SSH protocols, credentials, submodules, build scripts, or LFS smudge. GitHub repository URLs auto-detect as git; other providers may need the Git override. |
| ELF, PE/EXE/DLL, Mach-O/SO/DYLIB | `file`, LIEF headers/sections/imports/exports/libraries, bounded strings, Shannon entropy, packer markers, REA hardening checks, secret/SAST review of extracted strings | No target execution or automatic unpacking. High entropy is not proof of packing or malware. Ghidra-headless is **not enabled** in this deployment; no native pseudocode is claimed. |
| APK | Safe extraction, Androguard binary XML/ARSC decoding, permissions/components, flags, network-security XML, JADX DEX decompilation, resource strings, secret/SAST checks | No emulator, device access, dynamic instrumentation, signature bypass, or server probing. Missing flags do not establish effective Android defaults. |
| AAB | Bundletool manifest decoding, base-module metadata, extracted DEX through JADX, resources and source checks | Base module is selected. Resource coverage differs from a compiled APK. |
| IPA | Info.plist, ATS configuration, framework list, available `.xcent` and embedded XML entitlement blobs, executable strings, secret/SAST review | Linux-only static review. No iOS runtime/deep Objective-C/Swift reconstruction; encrypted App Store code and DER-only entitlements remain limited. |
| JS/TS/Python/Java/etc. | File inventory, applicable local Semgrep rules and gitleaks; REA module/import evidence plus beautification for JS/TS | Rule coverage varies by language. No source is evaluated or compiled. Static decoding is bounded to constant expressions; it is not a universal deobfuscator. |
| PNG/JPEG screenshot | Pillow validation/normalization, Tesseract English OCR, OCR text download, text scanning | 20 million pixels maximum; OCR can misread text. AI visual description/scaffolding is optional and disabled by default. |

The report distinguishes completed, partial, not applicable, and not enabled sections. Scanner matches are potential issues, not established exploitability. Gitleaks values are redacted in findings. Downloaded original/decompiled source artifacts can still contain sensitive source literals; keep them private. JSON/HTML retain fuller evidence than PDF, whose long sections are explicitly abbreviated.

## Architecture and isolation

- `unified/server.mjs`: Node HTTP server, existing account-verification flow, secure sessions, account acknowledgment, bounded uploads, durable job records, history, authenticated report/artifact downloads. It has **no Docker socket** and does not execute engines.
- `unified/runner.py`: host supervisor reads validated job UUIDs from `/var/lib/rea-workbench`, launches a fixed image/entrypoint, updates progress, enforces limits, logs failures, expires runs. No user-supplied shell commands are accepted.
- `unified/analyze.py`, `acquire.py`, `reporting.py`, `rules.yml`: worker orchestration, safe extraction/acquisition, static engine calls, unified reports, local SAST rules.
- `unified/egress.py`: public-only HTTP/HTTPS proxy. All DNS answers are validated; actual connection IPs are pinned. Loopback, private, link-local, reserved, multicast, mapped IPv6, custom ports, userinfo, and non-HTTP schemes are rejected. Redirect connections undergo the same check.
- Offline workers use `--network none`. URL/git workers use a **separate internal Docker network** `rea-fetch-isolated` (`172.30.44.0/28`). Host firewall rules allow that network to reach only its egress proxy at `172.30.44.1:3182`, then reject other host access. No worker ports are published.
- Workers run as uid/gid 1000 with a read-only root filesystem, no Linux capabilities, `no-new-privileges`, 3 GiB memory/no extra swap, two CPUs, 256 PIDs, 768 MiB temporary storage, 256 MiB shared memory, and a 10-minute static-analysis timeout. Output growth is stopped at 384 MiB. The renderer's own namespace sandbox is disabled for container compatibility; the worker container/network/resource restrictions remain its isolation boundary. Host OS/container vulnerabilities are outside this application's isolation guarantee.
- The worker receives only its own `/input` (read-only), `/request.json` (read-only), `/output` (writable), and deployment code (read-only). Existing sessions, password hashes, other clients' folders, the host root, and Docker socket are not mounted.
- The root supervisor owns container lifecycle. On supervisor restart, its run containers are stopped and interrupted jobs are reported as failed; queued jobs survive. Inspect logs with `journalctl -u rea-runner`.

### Default operational limits

48 MiB / 300 uploaded files; eight waiting/running jobs; 60 retained runs; eight-GiB workspace admission budget; one concurrent worker. Individual engine calls have shorter deadlines. An optional AI request adds up to 90 seconds plus report rendering after the static job. These limits are admissions/operational guards, not a universal proof against every malformed input.

## Setup on this existing VPS

The existing nginx login verifier at `172.16.4.1:3181/verify`, password file, Let's Encrypt certificate, domain record, nginx HTTPS configuration, and application network `rea-isolated` are reused. This repository includes their existing configuration for reference; do not reset credentials or DNS to reinstall the dashboard.

1. Place the contents of `deploy/auskal-workbench` under `/opt/rea-workbench`. Keep an application/nginx backup and do not replace `/var/lib/rea-workbench`, which holds existing sessions/history.
2. Build the small base runtime, then the heavier engine image:

   ```sh
   cd /opt/rea-workbench
   docker build -t auskal-rea:6.9.0 .
   docker build -f unified/Dockerfile.engines -t auskal-rea-engines:v2 unified
   ```

   The engine Dockerfile verifies official release SHA-256 digests for JADX 1.5.6, gitleaks 8.30.1, and Bundletool 1.18.3. Python installation versions are recorded inside the image at `/opt/engines/python-versions.txt`; the verified deployment copy is committed with the test record. `libatomic1` is required by the Playwright driver. JVM config/cache/home are redirected to writable per-worker `/tmp`, not the read-only image home.

3. Inspect existing host routes and Docker subnets before using the specified fetch subnet. Install/start the network guard and services:

   ```sh
   cp unified/rea-egress-firewall.service unified/rea-egress.service unified/rea-runner.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now rea-egress-firewall.service rea-egress.service rea-runner.service
   ```

4. Keep the current application container command (`node /app/server.mjs`). The root `server.mjs` imports the unified server. Existing read-only `/opt/rea-workbench:/app` and `/var/lib/rea-workbench:/data` mounts are retained. Restart only this container after staging the code:

   ```sh
   docker restart rea-workbench
   nginx -t
   python3 /opt/rea-workbench/smoke-test.py
   ```

No public REA MCP endpoint, arbitrary terminal, debugger, exploit runner, or automatic target execution is exposed by this dashboard.

## Optional Anthropic layer

**Off by default. No API calls or charges are made in the delivered default configuration.** To enable it deliberately, configure `/etc/rea-workbench/ai.env` (root-only) for the supervisor with `REA_AI_ENABLED=true`, `ANTHROPIC_API_KEY`, and an explicit `ANTHROPIC_MODEL`. Set `REA_AI_ENABLED=true` for the web container as well, then restart/recreate the relevant services. Do not place API keys in repository files, browser storage, or chat.

Each run still requires the user to select the AI opt-in checkbox. The checkbox states that redacted findings and the normalized screenshot, for image jobs, are sent to Anthropic and that charges may apply. Raw source, complete string inventories, scanner dumps, and credential values are omitted from the default text payload. AI can summarize findings, explain the available evidence, suggest fixes, and describe/scaffold screenshot UI approximately. Its output remains a separate AI interpretation section, never an engine verdict. The screenshot itself may contain private information; only opt in if sending it to Anthropic is intended.

The implementation uses the [Anthropic Messages API](https://platform.claude.com/docs/en/api/messages), with a configurable model and API version. **Live AI calls are not verified without API credentials.**

## Validation

- `test_safety.py`: archive traversal, links, expansion budgets, allowed extraction, public/private/mapped/multicast DNS, mixed DNS answers, URL scope.
- `test_e2e.py`: separate fixture account/server and queue, real sandboxed engines, automatic type detection, one-time acknowledgment, every input family, and JSON/HTML/PDF report downloads. Android fixtures are small public JADX test artifacts; the AAB/IPA and screenshot/source fixtures are benign synthetic test packages, not production applications.
- `test_ui.py`: isolated browser UI smoke tests with synthetic account/data, upload/drop/URL controls, progress, history, readable report, and downloads. It does not read or reset the production password.
- Production smoke check: existing HTTPS login page, redirect behavior, API access refusal, invalid-login/CSRF rejection, running services, and retained session storage.
- `verification.json` records the completed sample matrix and engine versions. Claims refer to those exact fixtures and checks, not all possible packages, websites, or file sizes.

For isolated testing, `test-api-harness.mjs` supplies a fake account verifier inside a non-public test container. **Never run that harness as the production web entrypoint.** The production account-verification URL stays unchanged.

## Maintenance and rollback

```sh
systemctl status rea-runner rea-egress rea-egress-firewall
journalctl -u rea-runner -n 50 --no-pager
docker logs --tail 50 rea-workbench
docker stats --no-stream rea-workbench
```

Before updates, back up code and nginx configuration. Keep sessions/history in place. To roll back, stop only `rea-runner`, restore the previous root `server.mjs`/frontend files from the deployment backup, and restart `rea-workbench`. Keep HTTPS and login enabled. New unified history files can remain until their normal expiry; old raw REA JSON reports remain readable in the unified dashboard.
