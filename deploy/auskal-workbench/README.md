# AusKal REA Workbench

A private, single-operator browser interface for REA's built-in static-analysis commands.
Runtime: the official npm package `rea-agents@6.9.0`, matching the version declared by this fork at deployment time. This deployment does not build or run the fork's unreleased source changes. The web interface is custom deployment code, not an upstream REA dashboard.

## Use

Open https://dev.auskal.tech and sign in with the existing GodsEye credentials.
Choose **Try a sample** for a JavaScript example, or choose files/folder and a compatible analysis.
Results retain REA Evidence and diagnostics and can be downloaded as JSON.

- 12 built-in static analysis modes; JavaScript/Electron, artifact identity, binary hardening/layout, entropy, .NET, APK signatures, Flutter identity, ELF notes, API contracts, Apple crashes.
- Maximum 48 MiB across 300 files; one active analysis; 120 second timeout; 12 MiB stdout cap.
- No arbitrary shell input, target execution, live URL fetching, public MCP endpoint, AI chat, or native decompiler is exposed by the web UI.
- Uploaded files and generated reports expire after 24 hours. Download reports before expiry.
- Failed or unsupported analysis shows its diagnostics. Deep native analysis requires an independently configured provider.

## Deployment layout

Application: /opt/rea-workbench  
Transient input and reports: /var/lib/rea-workbench (uid/gid 1000)  
Container: rea-workbench, image auskal-rea:6.9.0  
Internal network: rea-isolated, 172.16.4.0/24; container address 172.16.4.2  
Nginx: /etc/nginx/conf.d/dev.auskal.tech.conf  
TLS: /etc/letsencrypt/live/dev.auskal.tech; Certbot webroot /var/www/rea-acme

Nginx validates the existing shared password file. No password/hash is committed or copied into the container. All HTTP application routes are protected by nginx Basic authentication over HTTPS. HTTP redirects to HTTPS except ACME challenges.
The app runs as uid 1000 on a read-only root filesystem, with no capabilities, no-new-privileges, resource limits, and an internal Docker network without internet egress. It has no host root or Docker socket mount.

## Recreate on the same server

Check network allocation and existing configuration first. Do not reuse this subnet on a host where it overlaps another network.

```sh
mkdir -p /opt/rea-workbench /var/lib/rea-workbench /var/www/rea-acme
chown 1000:1000 /var/lib/rea-workbench
docker network inspect rea-isolated || docker network create --internal --subnet 172.16.4.0/24 rea-isolated
# Place these deployment files in /opt/rea-workbench.
cd /opt/rea-workbench
docker compose up -d --build
# Back up nginx configuration before applying nginx.conf.
nginx -t && systemctl reload nginx
```

The shared authentication file and a valid certificate must exist before enabling the HTTPS configuration. Never disable authentication to troubleshoot. Do not mount existing client projects or host secrets into the workbench.

## Operations

```sh
docker logs --tail 50 rea-workbench
docker stats --no-stream rea-workbench
docker restart rea-workbench
curl -I https://dev.auskal.tech/ # 401 without credentials is expected
python3 /opt/rea-workbench/smoke-test.py
```

The smoke test posts synthetic JavaScript files and a copy of the system's /bin/true for static inspection, confirms report downloads, and rejects traversal, unknown commands and untrusted Host/Origin. It creates temporary analysis records under the standard 24-hour expiry policy. It does not execute uploaded files.

## Verification performed

- Image build and JavaScript syntax verification passed.
- Runtime REA 6.9.0: actual JavaScript project, real ELF hardening, and entropy analysis completed with exit code 0.
- Report retrieval and input/command/origin/host rejection tests passed.
- Authoritative/public DNS resolves dev.auskal.tech to the selected VPS.
- Let's Encrypt certificate issued; scheduled renewal exists, with nginx reload deploy hook.
- HTTPS root/API require authentication; HTTP redirects to HTTPS.
- Full signed-in browser workflow remains subject to the operator's existing login. No password was read or reset during deployment.
