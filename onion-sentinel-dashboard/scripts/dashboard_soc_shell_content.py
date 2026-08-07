"""Pure static content fragments for the SOC dashboard shell."""
from __future__ import annotations


MOBILE_TRIAGE_CONTROLS = '''<div class="mobile-triage-bar" aria-label="Mobile alert triage controls"><div class="severity-chip-row"><button class="severity-chip active" type="button" data-severity-filter="all">All</button><button class="severity-chip sev-critical" type="button" data-severity-filter="critical">Critical</button><button class="severity-chip sev-high" type="button" data-severity-filter="high">High</button><button class="severity-chip sev-medium" type="button" data-severity-filter="medium">Medium</button><button class="severity-chip sev-low" type="button" data-severity-filter="low">Low</button><button class="severity-chip sev-informational" type="button" data-severity-filter="informational">Info</button></div><label class="mobile-sort-label">Sort <select id="mobile-sort"><option value="priority">Priority</option><option value="newest">Newest</option><option value="risk">Risk score</option></select></label></div>'''


ALERT_TABLE_COLUMN_STYLES = '''
    <style id="soc-alert-evidence-column-styles">
      .alert-table{min-width:1740px}
      .outcome-header,.outcome-cell{min-width:142px;text-align:center;white-space:nowrap}
      .pcap-size-header,.pcap-size-cell{min-width:96px;text-align:center;white-space:nowrap;font-variant-numeric:tabular-nums}
      .outcome-pill{display:inline-block;font-size:11px;font-weight:900;line-height:1.15;text-transform:uppercase;white-space:nowrap}
      .outcome-malicious{color:var(--red)}
      .outcome-suspicious{color:var(--orange)}
      .outcome-benign{color:var(--green)}
      .outcome-false-positive{color:var(--cyan)}
      .outcome-informational{color:#93c5fd}
      .outcome-inconclusive,.outcome-none{color:#94a3b8}
      .pinned-alert-row{grid-template-columns:42px 62px 74px 166px minmax(300px,1.25fr) minmax(126px,.68fr) minmax(126px,.68fr) 82px 112px 150px 112px 112px 96px 142px 62px 118px 38px}
      @media(max-width:1180px), (max-height:600px){.alert-table{min-width:0}}
    </style>
    '''


def render_alert_table_shell() -> str:
    """Render the API-backed alert table scaffold and its column contract."""
    table = f'''{MOBILE_TRIAGE_CONTROLS}<div class="mobile-alert-list" aria-label="Mobile SOC alert cards"></div><div class="table-card"><table class="alert-table"><thead><tr><th></th><th><button class="sort-header" type="button" data-sort-key="count">Count<span class="sort-indicator"></span></button></th><th class="severity-header"><button class="sort-header" type="button" data-sort-key="severity">Severity<span class="sort-indicator"></span></button></th><th><button class="sort-header" type="button" data-sort-key="last_seen">Last Seen<span class="sort-indicator"></span></button></th><th><button class="sort-header" type="button" data-sort-key="alert">Alert<span class="sort-indicator"></span></button></th><th class="ip-header"><button class="sort-header" type="button" data-sort-key="source_ip">Source IP<span class="sort-indicator"></span></button></th><th class="ip-header"><button class="sort-header" type="button" data-sort-key="destination_ip">Destination IP<span class="sort-indicator"></span></button></th><th class="port-header"><button class="sort-header" type="button" data-sort-key="destination_port">Destination Port<span class="sort-indicator"></span></button></th><th class="ai-header"><button class="sort-header" type="button" data-sort-key="ai">AI<span class="sort-indicator"></span></button></th><th class="enrichment-header"><button class="sort-header" type="button" data-sort-key="enrichment">Enrichment<span class="sort-indicator"></span></button></th><th class="pcap-header"><button class="sort-header" type="button" data-sort-key="pcap">PCAP<span class="sort-indicator"></span></button></th><th><button class="sort-header" type="button" data-sort-key="log_source">Log Source<span class="sort-indicator"></span></button></th><th><button class="sort-header" type="button" data-sort-key="size">Size<span class="sort-indicator"></span></button></th><th class="wide-only"><button class="sort-header" type="button" data-sort-key="risk">Risk<span class="sort-indicator"></span></button></th><th>Action</th><th></th></tr></thead></table><div class="api-pagination"><div class="api-page-size"><span>Rows</span><select id="api-page-size" aria-label="Rows per page"><option value="25" selected>25</option><option value="50">50</option><option value="75">75</option><option value="100">100</option><option value="250">250</option></select></div><div class="api-page-controls" aria-label="Alert table pagination"><button id="api-prev-page" class="ack-button api-page-button" type="button">Previous</button><select id="api-page-select" aria-label="Alert table page"><option value="1">Page 1</option></select><button id="api-next-page" class="ack-button api-page-button" type="button">Next</button></div><span id="api-alert-page-status" class="api-page-status">Loading alerts from SQLite API...</span><div class="api-table-metrics" aria-label="Alert table totals"><span class="api-table-metric"><b id="api-visible-total">0</b> Active</span><span class="api-table-metric suppressed"><b id="api-suppressed-total">0</b> Suppressed</span><span class="api-table-metric acknowledged"><b id="api-acknowledged-total">0</b> Acknowledged</span></div></div></div>'''
    table = table.replace(
        '<th class="enrichment-header">',
        '<th class="outcome-header">Detection Outcome</th><th class="enrichment-header">',
    )
    pcap_header = '<th class="pcap-header"><button class="sort-header" type="button" data-sort-key="pcap">PCAP<span class="sort-indicator"></span></button></th>'
    return table.replace(
        pcap_header, pcap_header + '<th class="pcap-size-header">PCAP Size</th>'
    ) + ALERT_TABLE_COLUMN_STYLES


def render_soc_overview(report_count: int) -> str:
    """Render the resilient intake flow overview with a live group count."""
    return f'''
    <section id="overview-view" class="view-section overview-view" aria-label="SOC Alerts overview">
      <div class="overview-grid">
        <section class="flow-hero" aria-label="Resilient SOC alert and evidence data flow">
          <div class="flow-copy">
            <span class="flow-kicker">Network flow</span>
            <h2>Resilient SOC Alert Intake & AI Triage</h2>
            <p>Alerts use a durable relay and SQLite-backed intake path. PCAP travels separately as read-only evidence, then enrichment, parsed packet findings, correlation context, and agent memory converge at the assigned analysis model.</p>
          </div>
          <div class="network-diagram" role="img" aria-label="Security Onion alert data flow diagram">
            <div class="flow-node node-so"><span class="node-icon">SO</span><strong>Security Onion</strong><span class="flow-ip-address" data-ip="192.168.1.7">xxx.xxx.xxx.xxx</span><em>Alert source</em></div>
            <div class="flow-link link-one"><span>restricted SSH poll</span></div>
            <div class="flow-node node-pi"><span class="node-icon">Pi</span><strong>Relay VLAN 888</strong><span class="flow-ip-address" data-ip="10.88.8.8">xxx.xxx.xxx.xxx</span><em>Transport only</em></div>
            <div class="flow-link link-two"><span>webhook POST</span></div>
            <div class="flow-node node-mac"><span class="node-icon">AI</span><strong>Mac Studio AI Lab</strong><span class="flow-ip-address" data-ip="10.77.7.225">xxx.xxx.xxx.xxx</span><em>n8n + SQLite</em></div>
            <div class="flow-fanout" aria-hidden="true"></div>
            <div class="flow-output output-dashboard"><b>Dashboard</b><span>Grouped Count rows</span></div>
            <div class="flow-output output-markdown"><b>Markdown</b><span>Reports + rollups</span></div>
            <div class="flow-output output-ai"><b>Assigned AI</b><span>Prompt packages</span></div>
            <div class="flow-output output-phone"><b>Telegram</b><span>High/critical only</span></div>
          </div>
        </section>
        <section class="overview-status" aria-label="Pipeline status">
          <div class="status-tile"><span>Source</span><strong>Security Onion</strong><em>Restricted export wrapper</em></div>
          <div class="status-tile"><span>Relay</span><strong>Raspberry Pi</strong><em>5 minute timer</em></div>
          <div class="status-tile"><span>Store</span><strong>SQLite</strong><em>{report_count} grouped detections</em></div>
          <div class="status-tile"><span>Analyst</span><strong>Assigned AI</strong><em>Daily rollups ready</em></div>
        </section>
      </div>
    </section>'''
