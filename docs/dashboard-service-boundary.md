# Dashboard Service Boundary

Onion Sentinel and the Hermes LAN Portal are separate applications. They share
a Mac Studio host, but they do not share build, publish, authentication,
runtime, or cleanup ownership.

## Runtime Ownership

| Component | Owner | Runtime path | Listener |
| --- | --- | --- | --- |
| Onion Sentinel source | Onion Sentinel | `$HOME/n8n-local/onion-sentinel-dashboard` | n/a |
| Onion Sentinel generated UI | Onion Sentinel | `$HOME/SOC Alerts Web` | `8766` |
| Onion Sentinel web/API service | Onion Sentinel | `com.arron.onion-sentinel.web` | `http://10.77.7.225:8766/` |
| Onion Sentinel listener guard | Onion Sentinel | `com.arron.onion-sentinel.web-guard` | Verifies port `8766` every 60 seconds |
| Hermes LAN Portal | Hermes | `$HOME/report_portal` and `$HOME/.hermes` | `http://10.77.7.225:8765/` |

The only supported relationship is a normal external link from the Hermes LAN
Portal to `http://10.77.7.225:8766/`.

The listener guard validates the JSON service identity rather than accepting a
generic HTTP success. It can terminate only the exact current-user
`python -m http.server 8766` collision and then kickstart Onion Sentinel's own
LaunchAgent. It refuses to kill an unknown listener and lets the stack monitor
raise an operator-visible failure instead. This keeps self-healing narrow and
prevents an unrelated process from being terminated automatically.

## Required Isolation

Hermes must not:

- run the Onion Sentinel dashboard builder;
- copy or mirror `$HOME/SOC Alerts Web`;
- serve, proxy, iframe, authenticate, or rewrite Onion Sentinel routes;
- scan or delete Onion Sentinel generated files as stale portal content;
- read or write the alert database, reports, beacon files, admin state, or
  dashboard runtime configuration;
- treat Hermes or OpenClaw availability as an Onion Sentinel health
  dependency.
- retain dormant Onion Sentinel builders, API modules, status files, or route
  handlers. Disabled code is still cross-project ownership and can be
  reactivated accidentally.

Onion Sentinel must not:

- execute scripts under `$HOME/.hermes`;
- write into `$HOME/report_portal`;
- depend on the Hermes portal service, its library, or its authentication
  state;
- deploy or repair Hermes-owned files.

## Supported Build Path

```text
$HOME/n8n-local/bin/refresh-soc-dashboard.py
  -> $HOME/n8n-local/onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py
  -> $HOME/SOC Alerts Web
  -> com.arron.onion-sentinel.web on TCP/8766
```

The refresh worker writes directly to the generated Onion Sentinel tree. There
is no portal synchronization step.

## Verification

Local source and optional live runtime checks are centralized in one command:

```bash
cd /path/to/OnionSentinel
MAC_HOST=<mac_user>@10.77.7.225 ./operations/verify-dashboard-isolation.zsh
```

The verifier requires:

- independent healthy listeners on ports `8765` and `8766`;
- a running `com.arron.onion-sentinel.web` LaunchAgent;
- a successful one-minute `com.arron.onion-sentinel.web-guard` check;
- an `onion_sentinel_server.py` process, rather than a generic directory
  server, owning port `8766`;
- no active Onion Sentinel reference to `.hermes` or `report_portal`;
- no legacy Onion Sentinel portal-copy helper or copied portal subtree;
- no Onion Sentinel builder/copy mapping in the Hermes sync job;
- no dormant SOC builder, API module, status file, runtime path, or SOC route
  handler in Hermes-owned files;
- old SOC API paths on port `8765` to fall through to the portal's normal
  `404` response;
- exactly one normal Hermes link to the independent Onion Sentinel URL.

Run this check after either project is deployed or upgraded. A failed boundary
check is a deployment failure even when both HTTP listeners return `200`.

## Recovery

If the services become coupled again:

1. Stop only the component performing the cross-project write.
2. Restore Onion Sentinel source from this repository into
   `$HOME/n8n-local/onion-sentinel-dashboard`.
3. Remove only the obsolete Onion Sentinel copy under the Hermes portal; do not
   delete unrelated portal content;
4. have the Hermes project owner remove any dormant SOC builder, API module,
   status file, and route handler from Hermes-owned paths;
5. rebuild with `$HOME/n8n-local/bin/refresh-soc-dashboard.py`;
6. restart `com.arron.onion-sentinel.web`;
7. restore only the Hermes portal's external link from within the Hermes
   project;
8. run the isolation verifier and the read-only Playwright suite.

Do not solve a boundary failure by copying runtime trees between projects.
