"""Pure data-flow page renderer and client assets."""
from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Mapping, Sequence


@dataclass(frozen=True)
class FlowPageViewModel:
    analysis_provider: str
    analysis_model: str
    analysis_icon: str
    total_groups: int
    total_observations: int
    ai_coverage: int
    urgent_groups: int
    ai_markdown_reports: int
    ai_json_reports: int
    telegram_critical: int
    telegram_high: int
    enrichment_tiles_html: str


def render_enrichment_service_tiles(services: Sequence[Mapping[str, str]]) -> str:
    """Render the owned enrichment-service catalog with escaped values."""
    tiles = []
    for service in services:
        name = html.escape(service['name'])
        scope = html.escape(service['scope'])
        note = html.escape(service['note'])
        asset = service.get('asset') or ''
        if asset:
            icon = f'<span class="enrichment-logo"><img src="{html.escape(asset)}" alt="{name} logo"></span>'
        else:
            fallback = html.escape(service.get('fallback', name[:1]))
            icon = f'<span class="enrichment-logo enrichment-logo-fallback" aria-hidden="true">{fallback}</span>'
        tiles.append(
            f'''<article class="enrichment-service" aria-label="{name} enrichment service">
              {icon}
              <div><strong>{name}</strong><span>{scope}</span></div>
              <em>{note}</em>
            </article>'''
        )
    return '\n'.join(tiles)


FLOW_PAGE_MARKUP = '''
    <section id="overview-view" class="view-section overview-view active flow-page-view" aria-label="Resilient alert intake, evidence enrichment, and AI triage data flow">
      <section class="flow-product-hero" aria-labelledby="flow-title">
        <button class="flow-privacy-toggle" type="button" aria-pressed="false" aria-label="Show node IP addresses" title="Show node IP addresses">
          <img src="assets/privacy-eye-button.png" alt="" aria-hidden="true">
        </button>
        <div class="flow-product-copy">
          <h2 id="flow-title">Resilient Alert, Evidence & AI Triage Pipeline</h2>
          <div class="flow-pulse-divider" aria-hidden="true"></div>
          <p>Alert JSON and packet evidence use separate durable paths. Alert-store commits analyst state and work queues first; enrichment, read-only PCAP collection, Zeek/TShark parsing, assigned-model correlation, reporting, and notification then continue independently.</p>
        </div>
        <div class="flow-product-map" aria-label="Current Onion Sentinel data flow">
          <div class="flow-stage-heading">
            <span>Alert path</span>
            <div><strong>Durable alert intake</strong><p>Transport, validation, grouping, and analyst state commit before asynchronous work begins.</p></div>
          </div>
          <div class="flow-lane flow-lane-ingress" aria-label="Durable alert intake path">
            <article class="flow-system-node">
              <span class="flow-logo-ring"><img src="assets/brand/security-onion.svg" alt="Security Onion logo"></span>
              <div><strong>Security Onion</strong><span class="flow-ip-address" data-ip="192.168.1.7">xxx.xxx.xxx.xxx</span></div>
              <em>read-only alert export</em>
            </article>
            <div class="flow-connector"><span>restricted SSH poll</span></div>
            <article class="flow-system-node">
              <span class="flow-logo-ring"><img src="assets/brand/raspberry-pi.svg" alt="Raspberry Pi logo"></span>
              <div><strong>Relay Alert Poller</strong><span class="flow-ip-address" data-ip="10.88.8.8">xxx.xxx.xxx.xxx</span></div>
              <em>durable SQLite outbox</em>
            </article>
            <div class="flow-connector"><span>webhook + heartbeat</span></div>
            <article class="flow-system-node">
              <span class="flow-logo-ring"><img src="assets/brand/n8n.svg" alt="n8n logo"></span>
              <div><strong>n8n Alert Workflow</strong><span>Docker on <span class="flow-ip-address" data-ip="10.77.7.225">xxx.xxx.xxx.xxx</span></span></div>
              <em>validate + normalize handoff</em>
            </article>
            <div class="flow-connector"><span>internal POST /alert</span></div>
            <article class="flow-system-node">
              <span class="flow-logo-ring"><img src="assets/brand/sqlite.svg" alt="SQLite logo"></span>
              <div><strong>alert-store Commit</strong><span>score, group, dedupe, state, durable jobs</span></div>
              <em>atomic SQLite source of truth</em>
            </article>
          </div>

          <div class="flow-downlink"><span>post-commit workers run independently with retryable durable state</span></div>

          <div class="flow-stage-heading">
            <span>Evidence workers</span>
            <div><strong>Independent enrichment and packet evidence</strong><p>Public lookups and bulk PCAP transport cannot block alert intake or one another.</p></div>
          </div>

          <section class="flow-enrichment-band" aria-label="Alert enrichment service layer">
            <article class="flow-system-node flow-enrichment-core">
              <span class="flow-logo-ring"><span>API</span></span>
              <div>
                <strong>alert-store enrichment worker</strong>
                <span>API-key gating, privacy checks, SQLite cache, rate limits</span>
              </div>
              <em>cache + normalize intel</em>
            </article>
            <div class="enrichment-service-grid" aria-label="Configured enrichment service catalog">
              {enrichment_tiles}
            </div>
          </section>

          <section class="flow-pcap-band" aria-label="Read-only PCAP evidence path">
            <div class="flow-route-caption">
              <span>PCAP evidence path</span>
              <p>n8n carries request metadata only. Packet bytes never travel inline or through the alert webhook.</p>
            </div>
            <div class="flow-lane flow-lane-pcap">
              <article class="flow-system-node">
                <span class="flow-logo-ring"><img src="assets/brand/security-onion.svg" alt="Security Onion logo"></span>
                <div><strong>Security Onion PCAP</strong><span>native capture rotations</span></div>
                <em>read-only bounded stream</em>
              </article>
              <div class="flow-connector"><span>restricted SSH stream</span></div>
              <article class="flow-system-node">
                <span class="flow-logo-ring"><span>SSD</span></span>
                <div><strong>Relay PCAP Broker</strong><span>1 TB SSD checkpoints and local artifact build</span></div>
                <em>isolated from alert polling</em>
              </article>
              <div class="flow-connector"><span>checksum + resumable rsync</span></div>
              <article class="flow-system-node">
                <span class="flow-logo-ring"><img src="assets/brand/apple.svg" alt="Apple logo"></span>
                <div><strong>Mac Artifact Intake</strong><span>restricted request and artifact verification</span></div>
                <em>durable intake + cleanup ack</em>
              </article>
              <div class="flow-connector"><span>verify + claim</span></div>
              <article class="flow-system-node">
                <span class="flow-logo-ring"><span>Z+T</span></span>
                <div><strong>Zeek + TShark</strong><span>structured findings and protocol corroboration</span></div>
                <em>bounded evidence; raw PCAP removed</em>
              </article>
            </div>
          </section>

          <div class="flow-downlink"><span>evidence merge: grouped alerts + enrichment + parsed PCAP + prior analyses + agent memory</span></div>

          <div class="flow-stage-heading">
            <span>Analysis and outputs</span>
            <div><strong>Assigned-model correlation, analyst state, reports, and notification</strong><p>The SOC Analyst receives bounded evidence through its exact enabled model route; durable state and analyst-facing artifacts remain rebuildable.</p></div>
          </div>

          <section class="flow-output-band" aria-label="Mac Studio hosted outputs and external notification">
            <section class="flow-mac-cluster" aria-label="Mac Studio hosted state analysis and dashboard services">
              <div class="flow-cluster-heading">
                <span class="flow-logo-ring"><img src="assets/brand/apple.svg" alt="Apple logo"></span>
                <div>
                  <strong>Mac Studio AI Lab</strong>
                  <span><span class="flow-ip-address" data-ip="10.77.7.225">xxx.xxx.xxx.xxx</span> hosted services</span>
                </div>
              </div>
              <div class="flow-cluster-grid">
                <article class="flow-system-node">
                  <span class="flow-logo-ring"><img src="assets/brand/sqlite.svg" alt="SQLite logo"></span>
                  <div>
                    <strong>SQLite</strong><span>alert-store backend</span>
                    <div class="flow-format-metrics" aria-label="SQLite alert-store metrics">
                      <span><b>{total_groups}</b><em>Grouped</em></span>
                      <span><b>{total_observations}</b><em>Observations</em></span>
                    </div>
                  </div>
                  <em>dashboard source</em>
                </article>
                <article class="flow-system-node">
                  <span class="flow-logo-ring"><img src="{analysis_icon}" alt="{analysis_provider} route icon"></span>
                  <div>
                    <strong>SOC Analyst AI</strong><span>{analysis_provider} · {analysis_model}</span>
                    <div class="flow-evidence-list" aria-label="SOC Analyst AI evidence inputs">
                      <span>group timeline</span><span>public intel</span><span>PCAP findings</span><span>correlation + memory</span>
                    </div>
                  </div>
                  <em>severity-priority assigned-model triage</em>
                </article>
                <article class="flow-system-node">
                  <div class="flow-logo-pair" aria-label="AI report output formats">
                    <span class="flow-logo-ring"><img src="assets/brand/obsidian.svg" alt="Obsidian logo"></span>
                    <span class="flow-logo-ring"><img src="assets/brand/json.svg" alt="JSON logo"></span>
                  </div>
                  <div>
                    <strong>AI Reports + Memory</strong><span>Markdown, JSON, per-agent and shared context</span>
                    <div class="flow-format-metrics" aria-label="AI report artifact formats">
                      <span><b>{ai_markdown_reports}</b><em>Markdown</em></span>
                      <span><b>{ai_json_reports}</b><em>JSON</em></span>
                    </div>
                  </div>
                  <em>findings + actions</em>
                </article>
                <article class="flow-system-node flow-dashboard-node">
                  <span class="flow-logo-ring"><img src="assets/onion-sentinel-logo.png" alt="Onion Sentinel logo"></span>
                  <div><strong>Onion Sentinel</strong><span>SOC analyst dashboard</span></div>
                  <div class="flow-node-metrics" aria-label="Onion Sentinel dashboard metrics">
                    <span><b>{total_groups}</b><em>Grouped</em></span>
                    <span><b>{total_observations}</b><em>Observations</em></span>
                    <span><b>{ai_coverage}%</b><em>AI coverage</em></span>
                    <span><b>{urgent_groups}</b><em>Critical/high</em></span>
                  </div>
                  <em>triage UI</em>
                </article>
              </div>
            </section>
            <section class="flow-external-cluster" aria-label="External notification delivery">
              <div class="flow-cluster-heading">
                <span class="flow-logo-ring"><img src="assets/brand/telegram.svg" alt="Telegram logo"></span>
                <div>
                  <strong>External notification</strong>
                  <span>High-signal mobile alerts</span>
                </div>
              </div>
              <article class="flow-system-node">
                <span class="flow-logo-ring"><img src="assets/brand/telegram.svg" alt="Telegram logo"></span>
                <div>
                  <strong>Telegram</strong><span>High and critical alerts</span>
                  <div class="flow-format-metrics" aria-label="Telegram notification metrics">
                    <span><b>{telegram_critical}</b><em>Critical</em></span>
                    <span><b>{telegram_high}</b><em>High</em></span>
                  </div>
                </div>
                <em>notification</em>
              </article>
            </section>
          </section>
        </div>
      </section>
      <section class="flow-summary-grid" aria-label="Pipeline service summary">
        <div class="flow-summary-card"><span>Alert source</span><strong>Security Onion</strong><em>Read-only restricted JSON export</em></div>
        <div class="flow-summary-card"><span>Alert transport</span><strong>Relay outbox</strong><em>Independent poller, retries, heartbeat</em></div>
        <div class="flow-summary-card"><span>Durable commit</span><strong>alert-store + SQLite</strong><em>Group, state, and job transaction</em></div>
        <div class="flow-summary-card"><span>Enrichment</span><strong>Public intel worker</strong><em>Privacy gates, cache, rate limits</em></div>
        <div class="flow-summary-card"><span>Packet evidence</span><strong>SSD + rsync + Zeek/TShark</strong><em>Read-only stream and verified cleanup</em></div>
        <div class="flow-summary-card"><span>Assigned AI triage</span><strong>{analysis_provider}</strong><em>{analysis_model}</em></div>
        <div class="flow-summary-card"><span>Analyst outputs</span><strong>Dashboard + reports</strong><em>SQLite, Markdown, JSON, memory</em></div>
        <div class="flow-summary-card"><span>Notification</span><strong>Telegram</strong><em>High/critical and health signals</em></div>
      </section>
    </section>'''


def render_flow_page(view: FlowPageViewModel) -> str:
    """Render the data-flow page from normalized runtime metrics."""
    return FLOW_PAGE_MARKUP.format(
        analysis_provider=html.escape(view.analysis_provider),
        analysis_model=html.escape(view.analysis_model),
        analysis_icon=html.escape(view.analysis_icon, quote=True),
        total_groups=view.total_groups,
        total_observations=view.total_observations,
        ai_coverage=view.ai_coverage,
        urgent_groups=view.urgent_groups,
        ai_markdown_reports=view.ai_markdown_reports,
        ai_json_reports=view.ai_json_reports,
        telegram_critical=view.telegram_critical,
        telegram_high=view.telegram_high,
        enrichment_tiles=view.enrichment_tiles_html,
    )



FLOW_PAGE_CSS = '''
<style>
.flow-page-view{display:block}
.flow-product-hero{position:relative;display:grid;grid-template-columns:minmax(260px,.34fr) minmax(760px,1fr);gap:22px;align-items:start;border:1px solid rgba(148,163,184,.14);border-radius:16px;padding:24px;background:linear-gradient(135deg,#0c151f 0%,#101923 58%,#071018 100%);box-shadow:0 22px 48px rgba(0,0,0,.24),inset 0 1px 0 rgba(255,255,255,.035)}
.flow-privacy-toggle{position:absolute;right:18px;top:18px;z-index:10;width:46px;height:46px;display:grid;place-items:center;border:1px solid rgba(34,211,238,.32);border-radius:15px;padding:0;background:rgba(7,16,24,.82);box-shadow:0 14px 30px rgba(0,0,0,.28),0 0 18px rgba(34,211,238,.10),inset 0 1px 0 rgba(255,255,255,.04);cursor:pointer;transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease}
.flow-privacy-toggle:hover{transform:translateY(-1px);border-color:rgba(143,244,255,.72);box-shadow:0 18px 38px rgba(0,0,0,.34),0 0 24px rgba(34,211,238,.22),inset 0 1px 0 rgba(255,255,255,.06)}
.flow-privacy-toggle[aria-pressed="true"]{border-color:rgba(143,244,255,.88);box-shadow:0 18px 38px rgba(0,0,0,.34),0 0 30px rgba(34,211,238,.30),inset 0 0 18px rgba(34,211,238,.07)}
.flow-privacy-toggle img{width:38px;height:38px;display:block;border-radius:12px;object-fit:cover;filter:drop-shadow(0 0 8px rgba(34,211,238,.18))}
.flow-product-copy{position:sticky;top:18px;display:flex;flex-direction:column;justify-content:center;min-width:0;padding:8px 2px 0}
.flow-product-copy h2{max-width:18ch;margin:8px 0 10px;color:#f5f9ff;font-size:24px;line-height:1.08;letter-spacing:-.025em}
.flow-product-copy p{max-width:50ch;margin:18px 0 0;color:#aab8ca;font-size:14px;line-height:1.62}
.flow-pulse-divider{width:100%;height:2px;margin-top:14px;border-radius:999px;background:linear-gradient(90deg,rgba(34,211,238,.14),rgba(143,244,255,.78),rgba(34,211,238,.14));box-shadow:0 0 10px rgba(34,211,238,.16);animation:flow-divider-pulse 2.8s ease-in-out infinite}
.flow-product-map{display:grid;gap:16px;min-width:0;border:1px solid rgba(34,211,238,.13);border-radius:14px;padding:18px;background:radial-gradient(circle at 78% 18%,rgba(34,211,238,.08),transparent 34%),linear-gradient(180deg,rgba(7,16,24,.62),rgba(6,12,20,.90))}
.flow-stage-heading{display:flex;align-items:flex-start;gap:12px;min-width:0;border-bottom:1px solid rgba(143,244,255,.14);padding:2px 2px 10px}
.flow-stage-heading>span{flex:0 0 auto;border:1px solid rgba(143,244,255,.22);border-radius:999px;padding:5px 8px;color:#8ff4ff;background:rgba(34,211,238,.045);font-size:9.5px;font-weight:950;letter-spacing:.09em;text-transform:uppercase}
.flow-stage-heading div{min-width:0}
.flow-stage-heading strong{display:block;color:#f4f8ff;font-size:14px;line-height:1.2}
.flow-stage-heading p{margin:4px 0 0;color:#91a4ba;font-size:11.5px;line-height:1.35}
.flow-lane{display:grid;grid-template-columns:minmax(150px,1fr) minmax(84px,.28fr) minmax(150px,1fr) minmax(84px,.28fr) minmax(150px,1fr) minmax(84px,.28fr) minmax(150px,1fr);gap:10px;align-items:center;min-width:0}
.flow-lane-outputs{grid-template-columns:repeat(6,minmax(128px,1fr))}
.flow-system-node{position:relative;display:grid;grid-template-rows:auto 1fr auto;gap:10px;min-width:0;min-height:150px;border:1px solid rgba(148,163,184,.15);border-radius:14px;padding:14px;background:rgba(10,18,27,.92);box-shadow:0 16px 38px rgba(0,0,0,.24),inset 0 1px 0 rgba(255,255,255,.035);transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease}
.flow-system-node:hover{transform:translateY(-2px);border-color:rgba(34,211,238,.32);box-shadow:0 20px 44px rgba(0,0,0,.30),0 0 24px rgba(34,211,238,.10),inset 0 1px 0 rgba(255,255,255,.045)}
.flow-logo-ring{width:52px;height:52px;display:grid;place-items:center;overflow:hidden;border:1px solid rgba(148,163,184,.16);border-radius:15px;background:rgba(255,255,255,.035);box-shadow:inset 0 0 20px rgba(34,211,238,.035)}
.flow-logo-ring img{width:36px;height:36px;margin:auto;object-fit:contain;object-position:center;display:block;filter:drop-shadow(0 0 8px rgba(34,211,238,.16))}
.flow-logo-ring img[alt="Security Onion logo"]{width:40px;height:40px}
.flow-logo-ring img[alt="Raspberry Pi logo"]{width:38px;height:38px}
.flow-logo-ring img[alt="Docker logo"],.flow-logo-ring img[alt="n8n logo"],.flow-logo-ring img[alt="SQLite logo"],.flow-logo-ring img[alt="Telegram logo"]{width:38px;height:38px}
.flow-logo-ring img[alt="Apple logo"]{width:34px;height:34px}
.flow-logo-ring img[alt="Ollama logo"]{width:34px;height:38px}
.flow-logo-ring img[alt="Onion Sentinel logo"]{width:44px;height:44px}
.flow-logo-ring span{color:#8ff4ff;font-size:13px;font-weight:950;letter-spacing:.06em}
.flow-logo-pair{display:flex;align-items:center;gap:8px;margin:0}
.flow-logo-pair .flow-logo-ring{margin:0!important}
.flow-system-node strong{display:block;color:#f4f8ff;font-size:15px;line-height:1.22}
.flow-system-node span:not(.flow-logo-ring):not(.flow-logo-ring span){display:block;margin-top:6px;color:#91a4ba;font-size:12px;line-height:1.35;overflow-wrap:anywhere}
.flow-ip-address{font-variant-numeric:tabular-nums;letter-spacing:.02em;color:#7f8fa3!important}
.flow-ip-address.visible{color:#91a4ba!important}
.flow-system-node em{align-self:end;color:#8ff4ff;font-size:10px;font-style:normal;font-weight:900;text-transform:uppercase;letter-spacing:.08em;line-height:1.2}
.flow-connector{--connector-y:48px;position:relative;display:grid;align-items:start;justify-items:center;min-width:88px;height:70px;background:linear-gradient(90deg,rgba(34,211,238,.16),rgba(143,244,255,.82),rgba(34,211,238,.16)) center var(--connector-y)/100% 2px no-repeat}
.flow-connector:before{content:"";position:absolute;left:0;top:var(--connector-y);width:8px;height:8px;border-radius:999px;background:#8ff4ff;box-shadow:0 0 0 4px rgba(34,211,238,.10),0 0 18px rgba(34,211,238,.75);transform:translate(-50%,-50%);animation:flow-dot-horizontal 3.6s linear infinite}
.flow-connector:after{content:"";position:absolute;right:-2px;top:var(--connector-y);width:9px;height:9px;border-top:2px solid #8ff4ff;border-right:2px solid #8ff4ff;transform:translateY(-50%) rotate(45deg)}
.flow-connector span{position:relative;z-index:1;max-width:calc(100% + 10px);white-space:normal;text-align:center;line-height:1.12;border:1px solid rgba(143,244,255,.22);border-radius:999px;padding:6px 7px;color:#dce9f8;background:rgba(7,16,24,.96);font-size:9px;font-weight:850;box-shadow:0 0 0 6px rgba(7,16,24,.78),0 0 16px rgba(0,0,0,.30)}
.flow-downlink{position:relative;display:grid;align-items:center;justify-items:center;min-height:58px}
.flow-downlink:before{content:"";position:absolute;top:0;bottom:0;left:50%;width:2px;background:linear-gradient(180deg,rgba(143,244,255,.82),rgba(34,211,238,.12));transform:translateX(-50%)}
.flow-downlink:after{content:"";position:absolute;bottom:2px;left:50%;width:9px;height:9px;border-right:2px solid #8ff4ff;border-bottom:2px solid #8ff4ff;transform:translateX(-50%) rotate(45deg)}
.flow-downlink span{position:relative;z-index:1;justify-self:center;width:max-content;max-width:min(680px,88%);margin:0;border:1px solid rgba(143,244,255,.22);border-radius:999px;padding:7px 13px;color:#dce9f8;background:rgba(7,16,24,.96);font-size:10.5px;font-weight:850;text-align:center;line-height:1.2;box-shadow:0 0 0 6px rgba(7,16,24,.78);overflow-wrap:anywhere}
.flow-enrichment-band{display:grid;grid-template-columns:minmax(230px,.28fr) minmax(520px,1fr);gap:14px;align-items:stretch;min-width:0;border:1px solid rgba(34,211,238,.16);border-radius:14px;padding:14px;background:rgba(34,211,238,.035);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.flow-enrichment-core{border-color:rgba(34,211,238,.34);box-shadow:0 16px 38px rgba(0,0,0,.22),0 0 26px rgba(34,211,238,.07),inset 0 1px 0 rgba(255,255,255,.04)}
.flow-pcap-band{display:grid;gap:12px;min-width:0;border:1px solid rgba(34,211,238,.16);border-radius:14px;padding:14px;background:linear-gradient(135deg,rgba(34,211,238,.035),rgba(7,16,24,.64));box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.flow-route-caption{display:flex;align-items:baseline;justify-content:space-between;gap:14px;min-width:0}
.flow-route-caption span{color:#8ff4ff;font-size:10px;font-weight:950;letter-spacing:.09em;text-transform:uppercase}
.flow-route-caption p{margin:0;color:#91a4ba;font-size:11px;line-height:1.35;text-align:right}
.enrichment-service-grid{display:grid;grid-template-columns:repeat(4,minmax(126px,1fr));gap:8px;min-width:0}
.enrichment-service{display:grid;grid-template-columns:34px minmax(0,1fr);grid-template-rows:auto auto;gap:7px 9px;align-items:center;min-width:0;border:1px solid rgba(148,163,184,.13);border-radius:11px;padding:9px;background:rgba(7,16,24,.72);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.enrichment-logo{grid-row:1 / 3;align-self:center;width:34px;height:34px;display:grid;place-items:center;overflow:hidden;border:1px solid rgba(34,211,238,.14);border-radius:10px;background:rgba(255,255,255,.035)}
.enrichment-logo img{width:23px;height:23px;margin:auto;object-fit:contain;object-position:center;display:block;filter:drop-shadow(0 0 6px rgba(34,211,238,.14))}
.enrichment-logo img[alt="Google Safe Browsing logo"],.enrichment-logo img[alt="urlscan.io logo"],.enrichment-logo img[alt="VirusTotal logo"]{width:24px;height:24px}
.enrichment-logo img[alt="CISA KEV logo"],.enrichment-logo img[alt="EPSS logo"],.enrichment-logo img[alt="NVD logo"]{width:25px;height:25px}
.enrichment-logo-fallback{color:#8ff4ff;font-size:15px;font-weight:950}
.enrichment-service strong{display:block;color:#f4f8ff;font-size:12px;line-height:1.15;overflow-wrap:anywhere}
.enrichment-service span:not(.enrichment-logo){display:block;margin-top:3px;color:#91a4ba;font-size:10.5px;line-height:1.22}
.enrichment-service em{grid-column:2;color:#8ff4ff;font-size:9.5px;font-style:normal;font-weight:900;text-transform:uppercase;letter-spacing:.07em}
.flow-node-metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;align-self:center;min-width:0}
.flow-node-metrics span,.flow-format-metrics span{display:grid!important;gap:3px;margin:0!important;min-width:0;border:1px solid rgba(34,211,238,.14);border-radius:10px;padding:7px 8px;background:rgba(34,211,238,.045);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.flow-node-metrics b,.flow-format-metrics b{color:#f5f9ff;font-size:13px;line-height:1;font-weight:950;font-variant-numeric:tabular-nums}
.flow-node-metrics em,.flow-format-metrics em{align-self:auto;color:#91a4ba;font-size:8.5px;line-height:1.1;font-style:normal;font-weight:850;letter-spacing:.05em;text-transform:uppercase;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.flow-format-metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:10px;min-width:0}
.flow-evidence-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px;margin-top:9px}
.flow-evidence-list span{margin:0!important;border:1px solid rgba(34,211,238,.12);border-radius:7px;padding:5px 6px;color:#aab8ca!important;background:rgba(34,211,238,.035);font-size:9px!important;line-height:1.15!important;text-align:center}
.flow-dashboard-node{border-color:rgba(34,211,238,.38);box-shadow:0 16px 42px rgba(0,0,0,.26),0 0 30px rgba(34,211,238,.08),inset 0 1px 0 rgba(255,255,255,.04)}
.flow-output-band{display:grid;grid-template-columns:minmax(640px,1fr) minmax(230px,.28fr);gap:14px;align-items:stretch;min-width:0}
.flow-mac-cluster,.flow-external-cluster{display:grid;grid-template-rows:auto 1fr;gap:12px;min-width:0;border:1px solid rgba(34,211,238,.16);border-radius:14px;padding:14px;background:rgba(7,16,24,.50);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.flow-mac-cluster{background:linear-gradient(135deg,rgba(34,211,238,.045),rgba(7,16,24,.58))}
.flow-external-cluster{border-color:rgba(34,211,238,.20);background:linear-gradient(135deg,rgba(34,211,238,.035),rgba(7,16,24,.66))}
.flow-cluster-heading{display:flex;align-items:center;gap:12px;min-width:0;padding-bottom:10px;border-bottom:1px solid rgba(148,163,184,.10)}
.flow-cluster-heading .flow-logo-ring{width:46px;height:46px;flex:0 0 46px;border-radius:13px}
.flow-cluster-heading .flow-logo-ring img{width:32px;height:32px}
.flow-cluster-heading strong{display:block;color:#f4f8ff;font-size:15px;line-height:1.15}
.flow-cluster-heading span:not(.flow-logo-ring):not(.flow-logo-ring span){display:block;margin-top:4px;color:#91a4ba;font-size:12px;line-height:1.25}
.flow-cluster-grid{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:10px;min-width:0}
.flow-output-band .flow-system-node{min-height:174px}
.flow-external-cluster .flow-system-node{min-height:0;height:100%}
@keyframes flow-dot-horizontal{0%{left:0;opacity:0;transform:translate(-50%,-50%) scale(.72)}10%,86%{opacity:1}100%{left:100%;opacity:0;transform:translate(-50%,-50%) scale(1.05)}}
@keyframes flow-divider-pulse{0%,100%{opacity:.46;box-shadow:0 0 8px rgba(34,211,238,.12)}50%{opacity:1;box-shadow:0 0 18px rgba(143,244,255,.34),0 0 34px rgba(34,211,238,.18)}}
.flow-summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-top:16px}
.flow-summary-card{border:1px solid rgba(148,163,184,.13);border-radius:12px;padding:16px;background:#0d1620;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.flow-summary-card span{display:block;color:#8ff4ff;font-size:11px;font-weight:950;text-transform:uppercase;letter-spacing:.10em}
.flow-summary-card strong{display:block;margin-top:10px;color:#f3f8ff;font-size:17px}
.flow-summary-card em{display:block;margin-top:6px;color:#9aa8b8;font-size:12px;font-style:normal;line-height:1.35}
@media(max-width:1700px){.flow-product-hero{grid-template-columns:1fr}.flow-product-copy{position:static;padding:0 64px 0 0}.flow-summary-grid{grid-template-columns:repeat(4,minmax(0,1fr))}}
@media(max-width:1280px){.flow-lane-ingress,.flow-lane-pcap{grid-template-columns:repeat(2,minmax(0,1fr))}.flow-lane-ingress .flow-connector,.flow-lane-pcap .flow-connector{display:none}.flow-lane-outputs{grid-template-columns:repeat(3,minmax(0,1fr))}.flow-enrichment-band,.flow-output-band{grid-template-columns:1fr}.enrichment-service-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.flow-cluster-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:820px){.flow-product-hero{padding:16px;border-radius:14px}.flow-product-copy{padding-right:58px}.flow-product-copy h2{font-size:28px}.flow-product-map{padding:12px}.flow-stage-heading,.flow-route-caption{display:grid;gap:7px}.flow-route-caption p{text-align:left}.flow-lane-ingress,.flow-lane-pcap,.flow-lane-outputs{grid-template-columns:1fr}.flow-lane-ingress .flow-system-node+.flow-system-node,.flow-lane-pcap .flow-system-node+.flow-system-node,.flow-lane-outputs .flow-system-node+.flow-system-node{margin-top:4px}.flow-downlink span{width:auto;max-width:90%}.enrichment-service-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.flow-summary-grid{grid-template-columns:1fr 1fr}}
@media(max-width:520px){.flow-product-copy{padding-right:0}.flow-privacy-toggle{position:relative;right:auto;top:auto;justify-self:end;margin-bottom:-6px}.flow-product-hero{display:grid;gap:12px}.flow-product-map{gap:12px}.flow-system-node{min-height:132px}.enrichment-service-grid,.flow-cluster-grid{grid-template-columns:1fr}.flow-summary-grid{grid-template-columns:1fr}.flow-node-metrics{grid-template-columns:1fr 1fr}}
</style>
'''

FLOW_PAGE_JS = '''
<script>
(() => {
  const buttons = [...document.querySelectorAll('.flow-privacy-toggle')];
  const addresses = [...document.querySelectorAll('.flow-ip-address')];
  if (!buttons.length || !addresses.length) return;
  const mask = 'xxx.xxx.xxx.xxx';
  let visible = false;
  function applyPrivacyState() {
    addresses.forEach(address => {
      address.textContent = visible ? (address.dataset.ip || '') : mask;
      address.classList.toggle('visible', visible);
    });
    buttons.forEach(button => {
      button.setAttribute('aria-pressed', String(visible));
      button.setAttribute('aria-label', visible ? 'Hide node IP addresses' : 'Show node IP addresses');
      button.setAttribute('title', visible ? 'Hide node IP addresses' : 'Show node IP addresses');
    });
  }
  buttons.forEach(button => button.addEventListener('click', () => {
    visible = !visible;
    applyPrivacyState();
  }));
  applyPrivacyState();
})();
</script>
'''


def inject_flow_assets(text: str) -> str:
    if FLOW_PAGE_CSS not in text:
        text = text.replace('</head>', FLOW_PAGE_CSS + '</head>', 1)
    if FLOW_PAGE_JS not in text:
        text = text.replace('</body>', FLOW_PAGE_JS + '</body>', 1)
    return text
