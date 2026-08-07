"""AC Hunter behavioral-triage page renderer."""
from __future__ import annotations


AC_HUNTER_PAGE_SECTION = r'''
    <section id="ac-hunter-deep-review-view" class="view-section active ac-hunter-view" aria-label="AC Hunter Deep Review">
      <div class="ac-hunter-hero">
        <div class="ac-hunter-hero-copy">
          <span class="ac-hunter-eyebrow">Behavioral network triage</span>
          <h2>Correlate AC Hunter findings before choosing the next investigation pivot</h2>
          <p>Review beaconing, long-lived sessions, unusual DNS, unexpected ports, blacklist matches, and scanning behavior in one evidence-focused workspace.</p>
          <p class="ac-hunter-disclaimer"><strong>Analyst guardrail:</strong> AC Hunter is a behavioral triage source. Scores and heuristics do not establish malware or compromise. Validate findings with primary network and endpoint evidence before reaching a conclusion.</p>
        </div>
        <div class="ac-hunter-refresh-panel">
          <span id="ac-hunter-cache-state" class="ac-hunter-cache-badge" data-state="loading">Loading cache</span>
          <button id="ac-hunter-refresh" type="button" aria-label="Reload stored AC Hunter snapshot">
            <span aria-hidden="true">↻</span> Reload stored snapshot
          </button>
          <small>PostgreSQL retains a rolling 24-hour history. A dedicated collector pulls through the Relay once an hour at 35 minutes after the hour and stores a new snapshot only when the dataset changes.</small>
        </div>
        <dl class="ac-hunter-metadata" aria-label="AC Hunter snapshot metadata">
          <div><dt>Dataset</dt><dd id="ac-hunter-dataset">security-onion-rolling</dd></div>
          <div><dt>Dataset start</dt><dd id="ac-hunter-range-start">Not available</dd></div>
          <div><dt>Dataset end</dt><dd id="ac-hunter-range-end">Not available</dd></div>
          <div><dt>Last pulled</dt><dd id="ac-hunter-last-pulled">Not yet loaded</dd></div>
        </dl>
      </div>

      <div id="ac-hunter-loading" class="ac-hunter-state" role="status" aria-live="polite">Loading the latest cached AC Hunter deep review…</div>
      <div id="ac-hunter-stale" class="ac-hunter-state ac-hunter-state-warning" role="status" aria-live="polite" hidden>The cached AC Hunter snapshot is stale. Findings remain visible with their original collection time; confirm freshness before acting.</div>
      <div id="ac-hunter-error" class="ac-hunter-state ac-hunter-state-error" role="alert" hidden></div>

      <section class="ac-hunter-verdict-section" aria-labelledby="ac-hunter-verdict-title">
        <div class="ac-hunter-section-heading">
          <div><span class="ac-hunter-eyebrow">Analyst verdicts</span><h2 id="ac-hunter-verdict-title">Prioritized behavioral findings</h2></div>
          <p>Deterministic triage labels explain urgency without asserting malware.</p>
        </div>
        <div class="ac-hunter-verdict-grid">
          <article class="ac-hunter-verdict-card verdict-high"><span>High concern</span><strong data-ac-hunter-verdict-count="high_concern">0</strong><small>Multiple strong risk signals or direct reputation/scanning evidence</small></article>
          <article class="ac-hunter-verdict-card verdict-review"><span>Needs review</span><strong data-ac-hunter-verdict-count="needs_review">0</strong><small>Important ambiguity that warrants analyst validation</small></article>
          <article class="ac-hunter-verdict-card verdict-benign"><span>Likely benign</span><strong data-ac-hunter-verdict-count="likely_benign">0</strong><small>Behavior is explained by a recognized service or expected use</small></article>
          <article class="ac-hunter-verdict-card verdict-info"><span>Informational</span><strong data-ac-hunter-verdict-count="informational">0</strong><small>Context retained for correlation without elevated priority</small></article>
        </div>
      </section>

      <section class="ac-hunter-notes-panel" aria-labelledby="ac-hunter-notes-title">
        <div class="ac-hunter-section-heading">
          <div><span class="ac-hunter-eyebrow">Analyst Notes</span><h2 id="ac-hunter-notes-title">Findings that need deliberate review</h2></div>
          <p>Use these leads to choose targeted Security Onion, Zeek, PCAP, or endpoint pivots.</p>
        </div>
        <div id="ac-hunter-notes" class="ac-hunter-note-list">
          <p class="ac-hunter-empty">Waiting for the latest AC Hunter snapshot.</p>
        </div>
      </section>

      <div class="ac-hunter-correlation-grid">
        <section class="ac-hunter-panel" aria-labelledby="ac-hunter-risky-hosts-title">
          <div class="ac-hunter-section-heading">
            <div><span class="ac-hunter-eyebrow">Host risk</span><h2 id="ac-hunter-risky-hosts-title">Top risky internal hosts</h2></div>
          </div>
          <div id="ac-hunter-risky-hosts" class="ac-hunter-host-list">
            <p class="ac-hunter-empty">Waiting for dashboard scores.</p>
          </div>
        </section>
        <section class="ac-hunter-panel" aria-labelledby="ac-hunter-correlated-hosts-title">
          <div class="ac-hunter-section-heading">
            <div><span class="ac-hunter-eyebrow">Cross-module</span><h2 id="ac-hunter-correlated-hosts-title">Correlated host summary</h2></div>
          </div>
          <div id="ac-hunter-correlated-hosts" class="ac-hunter-host-list">
            <p class="ac-hunter-empty">Waiting for cross-module correlation.</p>
          </div>
        </section>
      </div>

      <div class="ac-hunter-module-grid">
        <section class="ac-hunter-module" aria-labelledby="ac-hunter-beacons-title">
          <div class="ac-hunter-module-heading"><div><span class="ac-hunter-eyebrow">Periodic traffic</span><h2 id="ac-hunter-beacons-title">Beaconing detections</h2></div><span id="ac-hunter-beacons-count" class="ac-hunter-count">0</span></div>
          <div class="ac-hunter-table-wrap"><table class="ac-hunter-beacons-table"><thead><tr><th>Source</th><th>Destination / FQDN</th><th>Score</th><th>Connections</th><th>Timing mode</th><th>Data-size mode</th><th>Verdict</th></tr></thead><tbody id="ac-hunter-beacons-body"><tr><td colspan="7">Loading beacon findings…</td></tr></tbody></table></div>
        </section>
        <section class="ac-hunter-module" aria-labelledby="ac-hunter-sni-title">
          <div class="ac-hunter-module-heading"><div><span class="ac-hunter-eyebrow">TLS context</span><h2 id="ac-hunter-sni-title">SNI beacon detections</h2></div><span id="ac-hunter-sni-count" class="ac-hunter-count">0</span></div>
          <div class="ac-hunter-table-wrap"><table><thead><tr><th>Source</th><th>FQDN</th><th>Responding IPs</th><th>Score</th><th>Connections</th><th>Verdict</th></tr></thead><tbody id="ac-hunter-sni-body"><tr><td colspan="6">Loading SNI beacon findings…</td></tr></tbody></table></div>
        </section>
        <section class="ac-hunter-module" aria-labelledby="ac-hunter-proxy-title">
          <div class="ac-hunter-module-heading"><div><span class="ac-hunter-eyebrow">Proxy behavior</span><h2 id="ac-hunter-proxy-title">Proxy beacon detections</h2></div><span id="ac-hunter-proxy-count" class="ac-hunter-count">0</span></div>
          <div class="ac-hunter-table-wrap"><table><thead><tr><th>Source</th><th>Destination / FQDN</th><th>Score</th><th>Connections</th><th>Port / protocol</th><th>Verdict</th></tr></thead><tbody id="ac-hunter-proxy-body"><tr><td colspan="6">Loading proxy beacon findings…</td></tr></tbody></table></div>
        </section>
        <section class="ac-hunter-module" aria-labelledby="ac-hunter-long-title">
          <div class="ac-hunter-module-heading"><div><span class="ac-hunter-eyebrow">Duration</span><h2 id="ac-hunter-long-title">Long connections over 5 hours</h2></div><span id="ac-hunter-long-count" class="ac-hunter-count">0</span></div>
          <div class="ac-hunter-table-wrap"><table><thead><tr><th>Source</th><th>Destination / FQDN</th><th>Duration</th><th>Port / protocol</th><th>Connections</th><th>Verdict</th></tr></thead><tbody id="ac-hunter-long-body"><tr><td colspan="6">Loading long-connection findings…</td></tr></tbody></table></div>
        </section>
        <section class="ac-hunter-module" aria-labelledby="ac-hunter-dns-title">
          <div class="ac-hunter-module-heading"><div><span class="ac-hunter-eyebrow">Name resolution</span><h2 id="ac-hunter-dns-title">DNS anomalies</h2></div><span id="ac-hunter-dns-count" class="ac-hunter-count">0</span></div>
          <div class="ac-hunter-table-wrap"><table><thead><tr><th>Source</th><th>FQDN / query</th><th>Destination</th><th>Count</th><th>Score</th><th>Verdict</th></tr></thead><tbody id="ac-hunter-dns-body"><tr><td colspan="6">Loading DNS anomaly findings…</td></tr></tbody></table></div>
        </section>
        <section class="ac-hunter-module" aria-labelledby="ac-hunter-unexpected-title">
          <div class="ac-hunter-module-heading"><div><span class="ac-hunter-eyebrow">Protocol use</span><h2 id="ac-hunter-unexpected-title">Unexpected protocol / port findings</h2></div><span id="ac-hunter-unexpected-count" class="ac-hunter-count">0</span></div>
          <div class="ac-hunter-table-wrap"><table><thead><tr><th>Source</th><th>Destination / FQDN</th><th>Port / protocol</th><th>Count</th><th>Evidence</th><th>Verdict</th></tr></thead><tbody id="ac-hunter-unexpected-body"><tr><td colspan="6">Loading unexpected-port findings…</td></tr></tbody></table></div>
        </section>
        <section class="ac-hunter-module" aria-labelledby="ac-hunter-blacklist-title">
          <div class="ac-hunter-module-heading"><div><span class="ac-hunter-eyebrow">Reputation context</span><h2 id="ac-hunter-blacklist-title">Blacklist results</h2></div><span id="ac-hunter-blacklist-count" class="ac-hunter-count">0</span></div>
          <div class="ac-hunter-table-wrap"><table><thead><tr><th>Source</th><th>Destination</th><th>FQDN</th><th>Score / count</th><th>Evidence</th><th>Verdict</th></tr></thead><tbody id="ac-hunter-blacklist-body"><tr><td colspan="6">Loading blacklist results…</td></tr></tbody></table></div>
        </section>
        <section class="ac-hunter-module" aria-labelledby="ac-hunter-strobe-title">
          <div class="ac-hunter-module-heading"><div><span class="ac-hunter-eyebrow">Connection fan-out</span><h2 id="ac-hunter-strobe-title">Strobe / scanning results</h2></div><span id="ac-hunter-strobe-count" class="ac-hunter-count">0</span></div>
          <div class="ac-hunter-table-wrap"><table><thead><tr><th>Source</th><th>Destination</th><th>Connections</th><th>Port / protocol</th><th>Evidence</th><th>Verdict</th></tr></thead><tbody id="ac-hunter-strobe-body"><tr><td colspan="6">Loading strobe results…</td></tr></tbody></table></div>
        </section>
      </div>
    </section>
    <style>
      .ac-hunter-view{display:block;min-width:0;padding:0 0 30px}.ac-hunter-hero{display:grid;grid-template-columns:minmax(0,1fr) minmax(250px,340px);gap:18px;margin-bottom:16px;padding:22px;border:1px solid #184352;border-radius:12px;background:linear-gradient(135deg,#0d1b26,#0a151f);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.ac-hunter-hero-copy{min-width:0}.ac-hunter-eyebrow{display:block;margin-bottom:6px;color:#75efff;font-size:.7rem;font-weight:950;letter-spacing:.12em;text-transform:uppercase}.ac-hunter-hero h2,.ac-hunter-section-heading h2,.ac-hunter-module-heading h2{margin:0;color:#eef5ff}.ac-hunter-hero h2{max-width:820px;font-size:1.5rem;line-height:1.2}.ac-hunter-hero-copy>p{max-width:900px;margin:9px 0 0;color:#9caec2;font-size:.84rem;line-height:1.55}.ac-hunter-disclaimer{padding:11px 13px;border-left:3px solid #ffca67;color:#f2d693!important;background:rgba(255,202,103,.06)}.ac-hunter-disclaimer strong{color:#ffca67}.ac-hunter-refresh-panel{display:grid;align-content:center;justify-items:start;gap:10px;padding:16px;border:1px solid #223341;border-radius:10px;background:#09131d}.ac-hunter-refresh-panel button{min-height:44px;padding:0 14px;border:1px solid #08708a;border-radius:8px;color:#eaf8ff;background:#0a2530;font-weight:900;cursor:pointer}.ac-hunter-refresh-panel button:hover,.ac-hunter-refresh-panel button:focus-visible{border-color:#35d9ec;color:#75efff}.ac-hunter-refresh-panel button:disabled{opacity:.5;cursor:wait}.ac-hunter-refresh-panel button[aria-busy="true"] span{display:inline-block;animation:ac-hunter-spin .8s linear infinite}.ac-hunter-refresh-panel small{color:#8397ab;line-height:1.4}.ac-hunter-cache-badge,.ac-hunter-count,.ac-hunter-verdict{display:inline-flex;align-items:center;width:max-content;border:1px solid currentColor;border-radius:999px;padding:4px 8px;font-size:.64rem;font-weight:950;text-transform:uppercase;letter-spacing:.04em}.ac-hunter-cache-badge[data-state="fresh"]{color:#69e89a}.ac-hunter-cache-badge[data-state="stale"]{color:#ffca67}.ac-hunter-cache-badge[data-state="error"]{color:#ff6681}.ac-hunter-cache-badge[data-state="loading"]{color:#75efff}.ac-hunter-metadata{grid-column:1/-1;display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0}.ac-hunter-metadata div{min-width:0;padding:11px 13px;border:1px solid #223341;border-radius:8px;background:#0b1721}.ac-hunter-metadata dt{color:#8397ab;font-size:.66rem;font-weight:900;text-transform:uppercase}.ac-hunter-metadata dd{margin:5px 0 0;color:#d8e7f8;font:700 .76rem/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.ac-hunter-state{margin-bottom:14px;padding:11px 13px;border:1px solid #184352;border-radius:8px;color:#b9d6e8;background:#0a1923;font-size:.8rem}.ac-hunter-state-warning{border-color:#755d27;color:#f5d58b;background:#211b10}.ac-hunter-state-error{border-color:#7f3345;color:#ffb8c3;background:#25131a}.ac-hunter-verdict-section,.ac-hunter-notes-panel,.ac-hunter-panel,.ac-hunter-module{min-width:0;margin-bottom:16px;padding:18px;border:1px solid #223341;border-radius:10px;background:#0a151f}.ac-hunter-section-heading,.ac-hunter-module-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;margin-bottom:14px}.ac-hunter-section-heading h2,.ac-hunter-module-heading h2{font-size:1.08rem}.ac-hunter-section-heading>p{max-width:600px;margin:0;color:#8fa2b8;font-size:.77rem;line-height:1.45;text-align:right}.ac-hunter-verdict-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.ac-hunter-verdict-card{min-width:0;padding:14px;border:1px solid #223341;border-radius:9px;background:#0b1721}.ac-hunter-verdict-card span,.ac-hunter-verdict-card small{display:block}.ac-hunter-verdict-card span{font-size:.72rem;font-weight:950;text-transform:uppercase}.ac-hunter-verdict-card strong{display:block;margin:7px 0 5px;font-size:1.5rem}.ac-hunter-verdict-card small{color:#8397ab;line-height:1.4}.verdict-high span,.verdict-high strong,.ac-hunter-verdict-high_concern{color:#ff6681}.verdict-review span,.verdict-review strong,.ac-hunter-verdict-needs_review{color:#ffca67}.verdict-benign span,.verdict-benign strong,.ac-hunter-verdict-likely_benign{color:#69e89a}.verdict-info span,.verdict-info strong,.ac-hunter-verdict-informational{color:#75efff}.ac-hunter-note-list,.ac-hunter-host-list{display:grid;gap:9px}.ac-hunter-note,.ac-hunter-host{min-width:0;padding:13px 14px;border:1px solid #223341;border-radius:8px;background:#0b1721}.ac-hunter-note[data-verdict="high_concern"]{border-left:3px solid #ff6681}.ac-hunter-note[data-verdict="needs_review"]{border-left:3px solid #ffca67}.ac-hunter-note h3,.ac-hunter-host h3{margin:0;color:#eef5ff;font-size:.86rem;overflow-wrap:anywhere}.ac-hunter-note p,.ac-hunter-host p{margin:6px 0 0;color:#a9bbce;font-size:.76rem;line-height:1.5;overflow-wrap:anywhere}.ac-hunter-note-meta,.ac-hunter-host-meta{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-top:9px;color:#8397ab;font:700 .68rem/1.4 ui-monospace,SFMono-Regular,Menlo,monospace}.ac-hunter-correlation-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.ac-hunter-correlation-grid .ac-hunter-panel{margin-bottom:16px}.ac-hunter-host-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.ac-hunter-module-grid{display:grid;gap:16px}.ac-hunter-module{margin:0}.ac-hunter-count{color:#75efff;background:#0a2530}.ac-hunter-table-wrap{max-width:100%;overflow-x:auto;border:1px solid #223341;border-radius:8px;background:#09131d}.ac-hunter-table-wrap table{width:100%;min-width:980px;border-collapse:collapse;table-layout:fixed}.ac-hunter-table-wrap th,.ac-hunter-table-wrap td{padding:10px 11px;text-align:left;vertical-align:top;border-bottom:1px solid #1e303d}.ac-hunter-table-wrap th{color:#9caec2;background:#101e2a;font-size:.69rem;text-transform:uppercase}.ac-hunter-table-wrap td{color:#cbd9e8;font-size:.76rem;line-height:1.45;overflow-wrap:anywhere}.ac-hunter-table-wrap tbody tr:hover td{background:#0e202b}.ac-hunter-cell-code{color:#d8e7f8;font:700 .74rem/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}.ac-hunter-cell-primary{display:block;color:#eef5ff;font-weight:850}.ac-hunter-cell-secondary{display:block;margin-top:4px;color:#8397ab;font-size:.7rem}.ac-hunter-verdict{margin-bottom:4px}.ac-hunter-reason{display:block;color:#9caec2;font-size:.7rem;line-height:1.45}.ac-hunter-empty{margin:0;padding:12px;border:1px dashed #315064;border-radius:8px;color:#8fa2b8;background:#09131d;font-size:.78rem;line-height:1.5}@keyframes ac-hunter-spin{to{transform:rotate(360deg)}}@media(max-width:1100px){.ac-hunter-verdict-grid,.ac-hunter-metadata{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:820px){.ac-hunter-hero,.ac-hunter-correlation-grid{grid-template-columns:1fr}.ac-hunter-refresh-panel{grid-row:3}.ac-hunter-metadata{grid-row:2}.ac-hunter-section-heading{display:block}.ac-hunter-section-heading>p{margin-top:7px;text-align:left}.ac-hunter-table-wrap{overflow:visible;border:0;background:transparent}.ac-hunter-table-wrap table,.ac-hunter-table-wrap tbody,.ac-hunter-table-wrap tr,.ac-hunter-table-wrap td{display:block;width:100%;min-width:0}.ac-hunter-table-wrap thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}.ac-hunter-table-wrap tbody{display:grid;gap:10px}.ac-hunter-table-wrap tr{padding:11px 13px;border:1px solid #223341;border-radius:8px;background:#09131d}.ac-hunter-table-wrap td{display:grid;grid-template-columns:minmax(110px,.34fr) minmax(0,1fr);gap:9px;padding:7px 0;border:0}.ac-hunter-table-wrap td:before{content:attr(data-label);color:#8397ab;font-size:.66rem;font-weight:900;text-transform:uppercase}.ac-hunter-table-wrap td[data-empty="true"]{display:block}.ac-hunter-table-wrap td[data-empty="true"]:before{content:none}}@media(max-width:560px){.ac-hunter-hero{padding:16px}.ac-hunter-verdict-grid,.ac-hunter-metadata{grid-template-columns:1fr}.ac-hunter-refresh-panel button{width:100%}.ac-hunter-module-heading{align-items:center}.ac-hunter-table-wrap td{grid-template-columns:1fr;gap:3px}}
    </style>
    <style>
      .ac-hunter-verdict{white-space:nowrap}
      @media(min-width:821px){
        .ac-hunter-table-wrap th:last-child,
        .ac-hunter-table-wrap td:last-child{width:280px}
        .ac-hunter-table-wrap .ac-hunter-beacons-table{
          display:block;
          min-width:1100px;
          border-collapse:separate;
          border-spacing:0;
          padding:0
        }
        .ac-hunter-beacons-table thead{display:block;padding:9px 9px 0}
        .ac-hunter-beacons-table tbody{display:grid;gap:9px;padding:9px}
        .ac-hunter-beacons-table tr{
          display:grid;
          grid-template-columns:minmax(max-content,1.05fr) minmax(180px,1.4fr) minmax(86px,.65fr) minmax(112px,.85fr) minmax(120px,.9fr) minmax(120px,.9fr) minmax(280px,2.2fr)
        }
        .ac-hunter-beacons-table th,
        .ac-hunter-beacons-table td{width:auto!important;min-width:0}
        .ac-hunter-beacons-table thead th{border-bottom:0}
        .ac-hunter-beacons-table td[colspan]{grid-column:1/-1}
        .ac-hunter-beacons-table th:first-child,
        .ac-hunter-beacons-table td:first-child{
          min-width:max-content;
          white-space:nowrap;
          overflow-wrap:normal;
          word-break:normal
        }
        .ac-hunter-beacons-table tbody td{
          padding:13px 14px;
          border-top:1px solid #223341;
          border-bottom:1px solid #223341;
          background:#0b1721
        }
        .ac-hunter-beacons-table tbody td:first-child{
          border-left:3px solid #223341;
          border-radius:8px 0 0 8px
        }
        .ac-hunter-beacons-table tbody td:last-child{
          border-right:1px solid #223341;
          border-radius:0 8px 8px 0
        }
        .ac-hunter-beacons-table tbody tr[data-verdict="high_concern"] td:first-child{border-left-color:#ff6681}
        .ac-hunter-beacons-table tbody tr[data-verdict="needs_review"] td:first-child{border-left-color:#ffca67}
        .ac-hunter-beacons-table tbody tr[data-verdict="likely_benign"] td:first-child{border-left-color:#69e89a}
        .ac-hunter-beacons-table tbody tr[data-verdict="informational"] td:first-child{border-left-color:#75efff}
      }
    </style>
    <script>
    (() => {
      const GET_ENDPOINT='/api/ac-hunter/deep-review';
      const loading=document.getElementById('ac-hunter-loading');
      const staleNotice=document.getElementById('ac-hunter-stale');
      const errorBox=document.getElementById('ac-hunter-error');
      const refreshButton=document.getElementById('ac-hunter-refresh');
      const cacheBadge=document.getElementById('ac-hunter-cache-state');
      let hasSnapshot=false;
      let loadPromise=null;

      const verdictOrder=['high_concern','needs_review','likely_benign','informational'];
      const verdictLabels={high_concern:'High concern',needs_review:'Needs review',likely_benign:'Likely benign',informational:'Informational'};
      const moduleAliases={
        beacons:['beacons','beaconing'],
        sni:['sni_beacons','beacons_sni','beaconssni'],
        proxy:['proxy_beacons','beacons_proxy','beaconsproxy'],
        long:['long_connections','longconns'],
        dns:['dns_anomalies','dns'],
        unexpected:['unexpected_ports','unexpected_protocols'],
        blacklist:['blacklist','blacklist_hits'],
        strobe:['strobe','strobe_scanning','scanning']
      };
      const emptyMessages={
        beacons:'No beacons were returned in this snapshot.',
        sni:'No SNI beacons were returned in this snapshot.',
        proxy:'No proxy beacons were returned in this snapshot.',
        long:'No connections over five hours were returned in this snapshot.',
        dns:'No DNS anomalies were returned in this snapshot.',
        unexpected:'No unexpected protocol or port findings were returned in this snapshot.',
        blacklist:'No blacklist matches were returned in this snapshot.',
        strobe:'No strobe or scanning findings were returned in this snapshot.'
      };
      const tableSpecs={
        beacons:{body:'ac-hunter-beacons-body',count:'ac-hunter-beacons-count',columns:[
          ['Source',f=>scalar(f.source_ip)],
          ['Destination / FQDN',f=>pair(f.destination_ip,f.fqdn)],
          ['Score',f=>score(f.score)],
          ['Connections',f=>integer(f.count)],
          ['Timing mode',f=>scalar(f.timing_mode)],
          ['Data-size mode',f=>scalar(f.data_size_mode)],
          ['Verdict',f=>verdictValue(f)]
        ]},
        sni:{body:'ac-hunter-sni-body',count:'ac-hunter-sni-count',columns:[
          ['Source',f=>scalar(f.source_ip)],
          ['FQDN',f=>scalar(f.fqdn)],
          ['Responding IPs',f=>listValue(f.responding_ips||f.destination_ips||f.destination_ip)],
          ['Score',f=>score(f.score)],
          ['Connections',f=>integer(f.count)],
          ['Verdict',f=>verdictValue(f)]
        ]},
        proxy:{body:'ac-hunter-proxy-body',count:'ac-hunter-proxy-count',columns:[
          ['Source',f=>scalar(f.source_ip)],
          ['Destination / FQDN',f=>pair(f.destination_ip,f.fqdn)],
          ['Score',f=>score(f.score)],
          ['Connections',f=>integer(f.count)],
          ['Port / protocol',f=>networkService(f)],
          ['Verdict',f=>verdictValue(f)]
        ]},
        long:{body:'ac-hunter-long-body',count:'ac-hunter-long-count',columns:[
          ['Source',f=>scalar(f.source_ip)],
          ['Destination / FQDN',f=>pair(f.destination_ip,f.fqdn)],
          ['Duration',f=>durationValue(f.duration)],
          ['Port / protocol',f=>networkService(f)],
          ['Connections',f=>integer(f.count)],
          ['Verdict',f=>verdictValue(f)]
        ]},
        dns:{body:'ac-hunter-dns-body',count:'ac-hunter-dns-count',columns:[
          ['Source',f=>scalar(f.source_ip)],
          ['FQDN / query',f=>scalar(f.fqdn)],
          ['Destination',f=>scalar(f.destination_ip)],
          ['Count',f=>integer(f.count)],
          ['Score',f=>score(f.score)],
          ['Verdict',f=>verdictValue(f)]
        ]},
        unexpected:{body:'ac-hunter-unexpected-body',count:'ac-hunter-unexpected-count',columns:[
          ['Source',f=>scalar(f.source_ip)],
          ['Destination / FQDN',f=>pair(f.destination_ip,f.fqdn)],
          ['Port / protocol',f=>networkService(f)],
          ['Count',f=>integer(f.count)],
          ['Evidence',f=>evidenceValue(f.evidence)],
          ['Verdict',f=>verdictValue(f)]
        ]},
        blacklist:{body:'ac-hunter-blacklist-body',count:'ac-hunter-blacklist-count',columns:[
          ['Source',f=>scalar(f.source_ip)],
          ['Destination',f=>scalar(f.destination_ip)],
          ['FQDN',f=>scalar(f.fqdn)],
          ['Score / count',f=>scoreCount(f)],
          ['Evidence',f=>evidenceValue(f.evidence)],
          ['Verdict',f=>verdictValue(f)]
        ]},
        strobe:{body:'ac-hunter-strobe-body',count:'ac-hunter-strobe-count',columns:[
          ['Source',f=>scalar(f.source_ip)],
          ['Destination',f=>scalar(f.destination_ip)],
          ['Connections',f=>integer(f.connection_count??f.count)],
          ['Port / protocol',f=>networkService(f)],
          ['Evidence',f=>evidenceValue(f.evidence)],
          ['Verdict',f=>verdictValue(f)]
        ]}
      };

      function node(tag,className,text){
        const element=document.createElement(tag);
        if(className)element.className=className;
        if(text!==undefined&&text!==null)element.textContent=String(text);
        return element;
      }
      function scalar(value,fallback='Not observed'){
        if(value===null||value===undefined||value==='')return fallback;
        if(Array.isArray(value))return value.length?value.map(item=>scalar(item,'')).filter(Boolean).join(', '):fallback;
        if(typeof value==='object'){
          try{return JSON.stringify(value)}catch(_){return fallback}
        }
        return String(value);
      }
      function listValue(value){return scalar(Array.isArray(value)?value:[value])}
      function integer(value){
        const parsed=Number(value);
        return Number.isFinite(parsed)?Math.max(0,Math.round(parsed)).toLocaleString():'Not observed';
      }
      function score(value){
        const parsed=Number(value);
        return Number.isFinite(parsed)?parsed.toFixed(parsed>=1?1:3):'Not scored';
      }
      function durationValue(value){
        const parsed=Number(value);
        if(!Number.isFinite(parsed))return scalar(value);
        if(parsed>=3600)return `${(parsed/3600).toFixed(2)} hours`;
        if(parsed>=60)return `${(parsed/60).toFixed(1)} minutes`;
        return `${parsed.toFixed(0)} seconds`;
      }
      function pair(primary,secondary){
        const first=scalar(primary,'');
        const second=scalar(secondary,'');
        return [first,second].filter(Boolean).join(' · ')||'Not observed';
      }
      function networkService(finding){
        const protocol=scalar(finding.protocol,'').toUpperCase();
        const port=scalar(finding.port,'');
        return [protocol,port].filter(Boolean).join('/')||'Not observed';
      }
      function evidenceValue(value){
        if(Array.isArray(value))return value.map(item=>scalar(item,'')).filter(Boolean).join(' · ')||'Not supplied';
        return scalar(value,'Not supplied');
      }
      function scoreCount(finding){
        const parts=[];
        if(finding.score!==undefined&&finding.score!==null&&finding.score!=='')parts.push(`score ${score(finding.score)}`);
        if(finding.count!==undefined&&finding.count!==null&&finding.count!=='')parts.push(`count ${integer(finding.count)}`);
        return parts.join(' · ')||'Not observed';
      }
      function token(value){
        const normalized=String(value||'informational').trim().toLowerCase().replace(/[\s-]+/g,'_');
        return verdictOrder.includes(normalized)?normalized:'informational';
      }
      function verdictValue(finding){
        return {kind:'verdict',verdict:token(finding.verdict),reason:scalar(finding.reason,'No analyst rationale supplied')};
      }
      function array(value){return Array.isArray(value)?value:[]}
      function firstObject(...values){return values.find(value=>value&&typeof value==='object'&&!Array.isArray(value))||{}}
      function firstValue(...values){return values.find(value=>value!==undefined&&value!==null&&value!=='')}
      function moduleItems(payload,key){
        const aliases=moduleAliases[key]||[key];
        const containers=[payload.modules,payload.findings,payload.data,payload].filter(value=>value&&typeof value==='object');
        for(const container of containers){
          for(const alias of aliases){
            if(Array.isArray(container[alias]))return container[alias];
            if(Array.isArray(container[alias]?.items))return container[alias].items;
            if(Array.isArray(container[alias]?.findings))return container[alias].findings;
          }
        }
        return [];
      }
      function appendValue(cell,value){
        if(value&&typeof value==='object'&&value.kind==='verdict'){
          const badge=node('span',`ac-hunter-verdict ac-hunter-verdict-${value.verdict}`,verdictLabels[value.verdict]);
          const reason=node('span','ac-hunter-reason',value.reason);
          cell.append(badge,reason);
          return;
        }
        cell.append(node('span','ac-hunter-cell-primary',scalar(value)));
      }
      function emptyRow(body,columnCount,message){
        const row=node('tr');
        const cell=node('td','',message);
        cell.colSpan=columnCount;
        cell.dataset.empty='true';
        row.append(cell);
        body.replaceChildren(row);
      }
      function renderTable(key,items,unavailable=false){
        const spec=tableSpecs[key];
        const body=document.getElementById(spec.body);
        document.getElementById(spec.count).textContent=String(items.length);
        if(!items.length){
          const message=unavailable
            ?'Data unavailable for this module. No conclusion can be drawn.'
            :emptyMessages[key];
          emptyRow(body,spec.columns.length,message);
          return;
        }
        const fragment=document.createDocumentFragment();
        items.forEach(finding=>{
          const row=node('tr');
          row.dataset.verdict=token(finding?.verdict);
          spec.columns.forEach(([label,getValue])=>{
            const cell=node('td');
            cell.dataset.label=label;
            appendValue(cell,getValue(finding&&typeof finding==='object'?finding:{}));
            row.append(cell);
          });
          fragment.append(row);
        });
        body.replaceChildren(fragment);
      }
      function renderVerdictCounts(payload,moduleData){
        const supplied=firstObject(payload.verdict_counts,payload.summary?.verdict_counts,payload.summary?.verdicts);
        const counts={high_concern:0,needs_review:0,likely_benign:0,informational:0};
        verdictOrder.forEach(key=>{
          const suppliedValue=firstValue(supplied[key],supplied[verdictLabels[key]],supplied[verdictLabels[key].toLowerCase()]);
          if(suppliedValue!==undefined)counts[key]=Number(suppliedValue)||0;
        });
        if(!Object.keys(supplied).length){
          Object.values(moduleData).flat().forEach(finding=>{counts[token(finding?.verdict)]+=1});
        }
        document.querySelectorAll('[data-ac-hunter-verdict-count]').forEach(element=>{
          element.textContent=String(counts[element.dataset.acHunterVerdictCount]||0);
        });
      }
      function addMeta(container,label,value){
        const item=node('span','',`${label}: ${scalar(value)}`);
        container.append(item);
      }
      function renderNotes(payload){
        const container=document.getElementById('ac-hunter-notes');
        const notes=array(firstValue(payload.analyst_notes,payload.notes));
        if(!notes.length){
          container.replaceChildren(node('p','ac-hunter-empty','No analyst notes were generated for this snapshot. This does not clear the environment; review module evidence and collection status.'));
          return;
        }
        const fragment=document.createDocumentFragment();
        notes.forEach(noteValue=>{
          const note=typeof noteValue==='object'&&noteValue!==null?noteValue:{reason:String(noteValue)};
          const verdict=token(note.verdict);
          const article=node('article','ac-hunter-note');
          article.dataset.verdict=verdict;
          const path=pair(note.source_ip,note.destination_ip);
          const title=firstValue(note.title,note.summary,path);
          article.append(node('h3','',scalar(title,'Analyst review item')));
          article.append(node('p','',scalar(firstValue(note.reason,note.evidence),'Review the correlated evidence and validate with a targeted pivot.')));
          const meta=node('div','ac-hunter-note-meta');
          meta.append(node('span',`ac-hunter-verdict ac-hunter-verdict-${verdict}`,verdictLabels[verdict]));
          if(note.source_ip||note.destination_ip)addMeta(meta,'Path',path);
          if(note.port||note.protocol)addMeta(meta,'Service',networkService(note));
          if(note.module)addMeta(meta,'Module',note.module);
          article.append(meta);
          fragment.append(article);
        });
        container.replaceChildren(fragment);
      }
      function renderHosts(payload){
        const risky=array(firstValue(payload.top_risky_internal_hosts,payload.top_hosts,payload.dashboard_hosts));
        const correlated=array(firstValue(payload.correlated_hosts,payload.host_correlations));
        renderHostList('ac-hunter-risky-hosts',risky,'No risky internal hosts were returned by the AC Hunter dashboard for this snapshot.',false);
        renderHostList('ac-hunter-correlated-hosts',correlated,'No internal host appeared across multiple AC Hunter modules in this snapshot.',true);
      }
      function renderHostList(containerId,items,emptyMessage,correlated){
        const container=document.getElementById(containerId);
        if(!items.length){
          container.replaceChildren(node('p','ac-hunter-empty',emptyMessage));
          return;
        }
        const fragment=document.createDocumentFragment();
        items.forEach(hostValue=>{
          const host=hostValue&&typeof hostValue==='object'?hostValue:{source_ip:hostValue};
          const verdict=token(host.verdict);
          const article=node('article','ac-hunter-host');
          const heading=node('div','ac-hunter-host-heading');
          heading.append(node('h3','',scalar(firstValue(host.source_ip,host.host,host.asset),'Unresolved internal host')));
          heading.append(node('span',`ac-hunter-verdict ac-hunter-verdict-${verdict}`,verdictLabels[verdict]));
          article.append(heading);
          article.append(node('p','',scalar(firstValue(host.reason,host.summary),correlated?'Observed across multiple behavioral modules.':'Review the dashboard score and supporting module evidence.')));
          const meta=node('div','ac-hunter-host-meta');
          const modules=array(firstValue(host.modules,host.module_names));
          if(modules.length)addMeta(meta,'Modules',modules.join(', '));
          const moduleCount=firstValue(host.module_count,modules.length||undefined);
          if(moduleCount!==undefined)addMeta(meta,'Module count',moduleCount);
          const hostScore=firstValue(host.score,host.risk_score,host.max_score);
          if(hostScore!==undefined)addMeta(meta,'Score',score(hostScore));
          const findingCount=firstValue(host.finding_count,host.count);
          if(findingCount!==undefined)addMeta(meta,'Findings',integer(findingCount));
          article.append(meta);
          fragment.append(article);
        });
        container.replaceChildren(fragment);
      }
      function displayTimestamp(value){
        if(!value)return 'Not available';
        const parsed=new Date(value);
        if(Number.isNaN(parsed.getTime()))return scalar(value);
        return parsed.toLocaleString(undefined,{dateStyle:'medium',timeStyle:'medium'});
      }
      function renderMetadata(payload){
        const dataset=typeof payload.dataset==='object'&&payload.dataset!==null?payload.dataset:{};
        const metadata=firstObject(payload.metadata);
        const range=firstObject(dataset.time_range,payload.time_range,metadata.time_range,payload.dataset_range);
        document.getElementById('ac-hunter-dataset').textContent=scalar(firstValue(dataset.name,payload.dataset_name,metadata.dataset,'security-onion-rolling'));
        document.getElementById('ac-hunter-range-start').textContent=displayTimestamp(firstValue(range.start,range.from,dataset.start,payload.range_start));
        document.getElementById('ac-hunter-range-end').textContent=displayTimestamp(firstValue(range.end,range.to,dataset.end,payload.range_end));
        document.getElementById('ac-hunter-last-pulled').textContent=displayTimestamp(firstValue(payload.last_pulled_at,payload.collected_at,payload.generated_at,payload.cache?.refreshed_at));
        const cache=firstObject(payload.cache);
        const isStale=payload.stale===true||cache.stale===true||String(firstValue(cache.status,payload.cache_status,'')).toLowerCase()==='stale';
        cacheBadge.dataset.state=isStale?'stale':'fresh';
        cacheBadge.textContent=isStale
          ?'Stale cache'
          :scalar(firstValue(cache.status,payload.cache_status),'Fresh cache');
        cacheBadge.title=cache.storage_backend==='postgresql'
          ?`PostgreSQL rolling cache. Hourly collection runs at minute ${integer(firstValue(cache.scheduled_minute,35))}; ${integer(firstValue(cache.history_count,1))} distinct snapshot(s) retained.`
          :'';
        staleNotice.hidden=!isStale;
      }
      function render(payload){
        const moduleData={};
        Object.keys(tableSpecs).forEach(key=>{moduleData[key]=moduleItems(payload,key);renderTable(key,moduleData[key])});
        renderVerdictCounts(payload,moduleData);
        renderNotes(payload);
        renderHosts(payload);
        renderMetadata(payload);
        hasSnapshot=true;
        loading.hidden=true;
        errorBox.hidden=true;
      }
      function markUnavailable(message){
        Object.keys(tableSpecs).forEach(key=>renderTable(key,[],true));
        document.getElementById('ac-hunter-notes').replaceChildren(node('p','ac-hunter-empty','Analyst notes are unavailable because no AC Hunter snapshot could be loaded.'));
        document.getElementById('ac-hunter-risky-hosts').replaceChildren(node('p','ac-hunter-empty','Host risk data is unavailable. No risk conclusion can be drawn.'));
        document.getElementById('ac-hunter-correlated-hosts').replaceChildren(node('p','ac-hunter-empty','Cross-module correlation is unavailable. No correlation conclusion can be drawn.'));
        cacheBadge.dataset.state='error';
        cacheBadge.textContent='Unavailable';
        loading.hidden=true;
        errorBox.textContent=message;
        errorBox.hidden=false;
      }
      async function fetchJson(url,options={}){
        const controller=new AbortController();
        const timer=window.setTimeout(()=>controller.abort(),15000);
        try{
          const response=await fetch(url,{cache:'no-store',credentials:'same-origin',...options,signal:controller.signal});
          const payload=await response.json().catch(()=>null);
          if(!response.ok||!payload||payload.ok===false){
            const failure=new Error('AC Hunter request failed');
            failure.status=response.status;
            throw failure;
          }
          return payload;
        }finally{
          window.clearTimeout(timer);
        }
      }
      async function load({announce=false}={}){
        if(loadPromise)return loadPromise;
        if(announce&&!hasSnapshot){loading.hidden=false;loading.textContent='Loading the latest cached AC Hunter deep review…'}
        loadPromise=(async()=>{
          try{
            const payload=await fetchJson(GET_ENDPOINT);
            render(payload);
            return true;
          }catch(error){
            const status=Number(error?.status);
            const message=`AC Hunter data is temporarily unavailable${Number.isFinite(status)&&status>0?` (HTTP ${status})`:''}. ${hasSnapshot?'The last rendered snapshot remains visible; verify its collection time before acting.':'No conclusion can be drawn from missing data.'}`;
            if(hasSnapshot){
              errorBox.textContent=message;
              errorBox.hidden=false;
              staleNotice.hidden=false;
              cacheBadge.dataset.state='stale';
              cacheBadge.textContent='Stale cache';
              loading.hidden=true;
            }else{
              markUnavailable(message);
            }
            return false;
          }finally{
            loadPromise=null;
          }
        })();
        return loadPromise;
      }
      async function refresh(){
        if(refreshButton.disabled)return;
        refreshButton.disabled=true;
        refreshButton.setAttribute('aria-busy','true');
        errorBox.hidden=true;
        loading.hidden=false;
        loading.textContent='Reloading the latest AC Hunter snapshot from PostgreSQL…';
        try{
          const payload=await fetchJson(GET_ENDPOINT);
          render(payload);
        }catch(error){
          const status=Number(error?.status);
          errorBox.textContent=`AC Hunter refresh could not be completed${Number.isFinite(status)&&status>0?` (HTTP ${status})`:''}. ${hasSnapshot?'The previous snapshot remains visible.':'No conclusion can be drawn from missing data.'}`;
          errorBox.hidden=false;
          loading.hidden=true;
          if(hasSnapshot){
            staleNotice.hidden=false;
            cacheBadge.dataset.state='stale';
            cacheBadge.textContent='Stale cache';
          }else{
            markUnavailable(errorBox.textContent);
          }
        }finally{
          refreshButton.disabled=false;
          refreshButton.removeAttribute('aria-busy');
        }
      }
      refreshButton.addEventListener('click',refresh);
      load({announce:true});
      if(window.OnionSentinelReactiveTables){
        window.OnionSentinelReactiveTables.register('ac-hunter-deep-review',load,{intervalMs:60000,revisionKey:'ac_hunter'});
      }else{
        window.setInterval(load,60000);
      }
    })();
    </script>'''


def ac_hunter_page_section() -> str:
    """Render the cached, API-backed AC Hunter behavioral triage workspace."""
    return AC_HUNTER_PAGE_SECTION
