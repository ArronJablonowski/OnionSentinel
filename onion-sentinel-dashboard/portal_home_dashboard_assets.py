"""Static presentation assets for the Mac Studio LAN Portal home page."""

HOME_DASHBOARD_CSS = r"""
:root {
  --bg:#080b12; --panel:#0e1420; --panel2:#121a29; --muted:#8b98ac; --text:#edf3ff;
  --line:rgba(148,163,184,.18); --cyan:#23d3ee; --blue:#4f8cff; --green:#28e0a6; --amber:#f8c76a;
  --shadow:0 24px 80px rgba(0,0,0,.42); --radius:22px;
}
* { box-sizing:border-box }
body { margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--text); background:
  radial-gradient(circle at 14% -10%, rgba(35,211,238,.22), transparent 38%),
  radial-gradient(circle at 90% 4%, rgba(79,140,255,.18), transparent 34%),
  linear-gradient(180deg, #080b12 0%, #0a0f19 48%, #070910 100%); min-height:100vh; }
a { color:inherit; text-decoration:none }
.shell { width:min(1280px, calc(100% - 32px)); margin:0 auto; padding:26px 0 50px }
.hero { border:1px solid var(--line); background:linear-gradient(135deg, rgba(18,26,41,.92), rgba(8,11,18,.84)); border-radius:26px; padding:22px 24px; box-shadow:var(--shadow); position:relative; overflow:hidden }
.hero:after { content:""; position:absolute; inset:auto -80px -160px auto; width:300px; height:300px; background:radial-gradient(circle, rgba(40,224,166,.16), transparent 68%); pointer-events:none }
.hero-row { position:relative; z-index:2; display:flex; align-items:center; justify-content:space-between; gap:14px }
.hero-refresh { --refresh-accent:#23d3ee; --refresh-glow:rgba(35,211,238,.42); flex:0 0 auto; width:56px; height:56px; min-width:56px; min-height:56px; display:inline-flex; align-items:center; justify-content:center; border:1px solid rgba(35,211,238,.56); border-radius:22px; padding:0; color:var(--refresh-accent); background:linear-gradient(145deg, rgba(14,24,38,.78), rgba(7,15,25,.92)); box-shadow:0 16px 38px rgba(0,0,0,.28), inset 0 1px 0 rgba(255,255,255,.045), inset 0 -14px 30px rgba(6,12,22,.36), 0 0 0 1px rgba(35,211,238,.035); cursor:pointer; touch-action:manipulation; -webkit-tap-highlight-color:transparent; transition:transform .16s ease, border-color .16s ease, box-shadow .2s ease, filter .16s ease, background .2s ease; position:relative; overflow:hidden }
.hero-refresh:before { content:""; position:absolute; inset:1px; border:1px solid rgba(35,211,238,.18); border-radius:20px; background:radial-gradient(circle at 50% 45%, rgba(35,211,238,.10), transparent 58%); box-shadow:inset 0 0 20px rgba(35,211,238,.06); pointer-events:none }
.hero-refresh:after { content:""; position:absolute; inset:auto -24px -34px -24px; height:58%; background:radial-gradient(ellipse at 50% 100%, rgba(35,211,238,.10), transparent 66%); pointer-events:none }
.hero-refresh:hover { transform:translateY(-1px); border-color:rgba(35,211,238,.95); background:linear-gradient(145deg, rgba(16,31,46,.88), rgba(7,15,25,.94)); box-shadow:0 22px 54px rgba(0,0,0,.34), 0 0 18px rgba(35,211,238,.42), 0 0 44px rgba(35,211,238,.24), 0 0 76px rgba(35,211,238,.14), inset 0 1px 0 rgba(255,255,255,.065), inset 0 0 24px rgba(35,211,238,.08) }
.hero-refresh:hover:before { border-color:rgba(35,211,238,.34); box-shadow:inset 0 0 28px rgba(35,211,238,.12), 0 0 18px rgba(35,211,238,.12) }
.hero-refresh:active { transform:translateY(1px) scale(.99) }
.hero-refresh[aria-busy="true"], .hero-refresh.refreshing { cursor:wait; filter:saturate(1.18); border-color:rgba(35,211,238,1); box-shadow:0 22px 56px rgba(0,0,0,.34), 0 0 22px rgba(35,211,238,.52), 0 0 56px rgba(35,211,238,.30), 0 0 88px rgba(35,211,238,.18), inset 0 1px 0 rgba(255,255,255,.08), inset 0 0 28px rgba(35,211,238,.10) }
.hero-refresh-icon { position:relative; z-index:1; display:block; font-size:31px; line-height:1; transform-origin:center; color:var(--refresh-accent); text-shadow:0 0 10px rgba(35,211,238,.35), 0 0 24px rgba(35,211,238,.20) }
.hero-refresh:hover .hero-refresh-icon { text-shadow:0 0 12px rgba(35,211,238,.62), 0 0 30px rgba(35,211,238,.34), 0 0 54px rgba(35,211,238,.18) }
.hero-refresh[aria-busy="true"] .hero-refresh-icon, .hero-refresh.refreshing .hero-refresh-icon { animation:refresh-spin .72s linear infinite }
@keyframes refresh-spin { to { transform:rotate(360deg) } }
.kicker { display:inline-flex; gap:8px; align-items:center; color:var(--cyan); font-size:12px; letter-spacing:.16em; text-transform:uppercase; font-weight:800 }
h1 { font-size:clamp(30px, 4.4vw, 54px); line-height:.96; letter-spacing:-.055em; margin:10px 0 2px }
.subtitle { color:#b7c4d8; max-width:820px; font-size:17px; line-height:1.65; margin:0 }
.urls { display:flex; flex-wrap:wrap; gap:10px; margin-top:22px }
.urlpill { font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px; border:1px solid var(--line); background:rgba(15,23,42,.72); color:#d9e6f7; padding:10px 12px; border-radius:999px }
.stats { display:grid; grid-template-columns:repeat(5, minmax(0,1fr)); gap:14px; margin:18px 0 16px }
.stat { --accent:var(--cyan); --accent2:var(--green); position:relative; overflow:hidden; min-width:0; background:linear-gradient(145deg, color-mix(in srgb, var(--accent) 14%, rgba(18,26,41,.94)), rgba(10,16,27,.90) 58%, color-mix(in srgb, var(--accent2) 9%, rgba(8,12,20,.92))); border:1px solid color-mix(in srgb, var(--accent) 34%, rgba(148,163,184,.16)); border-radius:22px; padding:17px 16px 18px; box-shadow:0 16px 44px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.055); display:flex; flex-direction:column; gap:8px; isolation:isolate; transition:transform .16s ease, border-color .16s ease, box-shadow .16s ease; color:inherit; text-decoration:none; cursor:pointer }
.stat:before { content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, var(--accent), var(--accent2)); opacity:.95 }
.stat:after { content:""; position:absolute; width:120px; height:120px; right:-58px; top:-58px; border-radius:999px; background:radial-gradient(circle, color-mix(in srgb, var(--accent) 28%, transparent), transparent 68%); filter:blur(.2px); opacity:.78; z-index:-1 }
.stat:nth-child(1) { --accent:#23d3ee; --accent2:#4f8cff }
.stat:nth-child(2) { --accent:#f8c76a; --accent2:#ff7a90 }
.stat:nth-child(3) { --accent:#a78bfa; --accent2:#23d3ee }
.stat:nth-child(4) { --accent:#28e0a6; --accent2:#23d3ee }
.stat:nth-child(5) { --accent:#4f8cff; --accent2:#a78bfa }
.stat.stat-alert { --accent:#f8c76a; --accent2:#ff7a90 }
.stat.stat-ok { --accent:#28e0a6; --accent2:#23d3ee }
.stat:hover { transform:translateY(-2px); border-color:color-mix(in srgb, var(--accent) 58%, rgba(148,163,184,.18)); box-shadow:0 20px 56px rgba(0,0,0,.30), 0 0 0 1px color-mix(in srgb, var(--accent) 12%, transparent), inset 0 1px 0 rgba(255,255,255,.07) }
.stat span { order:1; color:color-mix(in srgb, var(--accent) 52%, #b7c4d8); font-size:11px; text-transform:uppercase; letter-spacing:.13em; font-weight:950; line-height:1.25 }
.stat strong { order:2; display:block; color:#f8fbff; font-size:clamp(21px, 2.1vw, 31px); line-height:1.05; letter-spacing:-.055em; overflow-wrap:anywhere; text-shadow:0 0 24px color-mix(in srgb, var(--accent) 20%, transparent) }
.mobile-apps { --quick-accent:#7dd3fc; --quick-accent2:#94a3b8; position:relative; margin:0 0 24px; padding:18px; border:1px solid color-mix(in srgb, var(--quick-accent) 24%, rgba(148,163,184,.16)); border-radius:24px; background:linear-gradient(145deg, color-mix(in srgb, var(--quick-accent) 8%, rgba(18,26,41,.94)), rgba(10,15,25,.91) 62%, color-mix(in srgb, var(--quick-accent2) 7%, rgba(8,12,20,.92))); box-shadow:0 16px 44px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.045); overflow:hidden; isolation:isolate }
.mobile-apps:before { content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, color-mix(in srgb, var(--quick-accent) 72%, #64748b), color-mix(in srgb, var(--quick-accent2) 72%, #475569)); opacity:.62 }
.mobile-apps:after { content:""; position:absolute; width:170px; height:170px; right:-96px; top:-96px; border-radius:999px; background:radial-gradient(circle, color-mix(in srgb, var(--quick-accent) 12%, transparent), transparent 70%); opacity:.72; z-index:-1 }
.mobile-apps h2 { color:#eef6ff; font-size:18px; line-height:1.05; letter-spacing:-.025em; margin:0 0 14px; text-shadow:0 0 18px color-mix(in srgb, var(--quick-accent) 10%, transparent) }
.app-strip { display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:12px }
.app-card { display:flex; gap:12px; align-items:center; border:1px solid rgba(35,211,238,.24); border-radius:22px; padding:16px; background:linear-gradient(135deg, rgba(35,211,238,.11), rgba(79,140,255,.07)); box-shadow:0 18px 54px rgba(0,0,0,.22) }
.app-card b { display:block; font-size:17px; letter-spacing:-.02em; margin-bottom:3px }
.app-card span { display:block; color:#b7c4d8; font-size:13px; line-height:1.35 }
.app-card .app-card-icon { width:54px; height:54px; flex:0 0 54px; display:flex; align-items:center; justify-content:center; border-radius:18px; font-size:34px; line-height:1; color:#eaf4ff; background:rgba(255,255,255,.08); border:1px solid var(--line); text-align:center; transform:translateY(0) }
.cron-menu { --cron-accent:#7dd3fc; --cron-accent2:#94a3b8; position:relative; margin:0 0 24px; border:1px solid color-mix(in srgb, var(--cron-accent) 24%, rgba(148,163,184,.16)); border-radius:24px; background:linear-gradient(145deg, color-mix(in srgb, var(--cron-accent) 8%, rgba(18,26,41,.94)), rgba(10,15,25,.91) 62%, color-mix(in srgb, var(--cron-accent2) 7%, rgba(8,12,20,.92))); box-shadow:0 16px 44px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.045); overflow:hidden; isolation:isolate }
.cron-menu:before { content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, color-mix(in srgb, var(--cron-accent) 72%, #64748b), color-mix(in srgb, var(--cron-accent2) 72%, #475569)); opacity:.62 }
.cron-menu:after { content:""; position:absolute; width:170px; height:170px; right:-96px; top:-96px; border-radius:999px; background:radial-gradient(circle, color-mix(in srgb, var(--cron-accent) 12%, transparent), transparent 70%); opacity:.72; z-index:-1 }
.cron-menu summary { min-height:68px; list-style:none; cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:14px; padding:17px 18px 16px; touch-action:manipulation }
.cron-menu summary::-webkit-details-marker { display:none }
.cron-summary-main { display:flex; align-items:center; gap:12px; min-width:0 }
.cron-summary-main b { display:block; color:#eef6ff; font-size:18px; line-height:1.05; letter-spacing:-.025em; text-shadow:0 0 18px color-mix(in srgb, var(--cron-accent) 10%, transparent) }
.cron-summary-main small { display:block; margin-top:5px; color:color-mix(in srgb, var(--cron-accent) 36%, #94a3b8); font-size:11px; font-weight:900; letter-spacing:.1em; text-transform:uppercase }
.cron-dot { width:12px; height:12px; border-radius:999px; background:color-mix(in srgb, var(--green) 70%, #94a3b8); box-shadow:0 0 18px rgba(40,224,166,.38); flex:0 0 auto }
.cron-chevron { color:#c8d6ea; font-size:24px; line-height:1; transition:transform .16s ease, color .16s ease }
.cron-menu:hover .cron-chevron { color:#e8f2ff }
.cron-menu[open] .cron-chevron { transform:rotate(180deg) }
.cron-panel { display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:12px; padding:0 12px 14px }
.cron-item { --job-accent:#7dd3fc; position:relative; overflow:hidden; border:1px solid color-mix(in srgb, var(--job-accent) 20%, rgba(148,163,184,.14)); border-radius:18px; background:linear-gradient(145deg, color-mix(in srgb, var(--job-accent) 7%, rgba(18,26,41,.88)), rgba(10,16,27,.82)); padding:14px; display:grid; gap:10px; box-shadow:0 12px 32px rgba(0,0,0,.16), inset 0 1px 0 rgba(255,255,255,.035) }
.cron-item:before { content:""; position:absolute; inset:0 0 auto 0; height:3px; background:linear-gradient(90deg, color-mix(in srgb, var(--job-accent) 58%, #64748b), rgba(148,163,184,.18)); opacity:.58 }
.cron-item:nth-child(2n) { --job-accent:#a78bfa }
.cron-item:nth-child(3n) { --job-accent:#28e0a6 }
.cron-item:nth-child(4n) { --job-accent:#f8c76a }
.cron-item.disabled { --job-accent:#94a3b8; opacity:.72; background:linear-gradient(145deg, rgba(18,26,41,.62), rgba(10,16,27,.58)) }
.cron-item-top { display:flex; align-items:flex-start; justify-content:space-between; gap:10px }
.cron-item-top strong { color:#edf5ff; font-size:15px; line-height:1.25; letter-spacing:-.01em }
.cron-status { flex:0 0 auto; font-size:10px; font-weight:950; text-transform:uppercase; letter-spacing:.09em; border-radius:999px; padding:5px 8px; border:1px solid rgba(40,224,166,.20); color:#a8f1dc; background:rgba(40,224,166,.065) }
.cron-status.disabled { color:#e8c989; background:rgba(248,199,106,.055); border-color:rgba(248,199,106,.18) }
.cron-next { display:grid; gap:4px; border-radius:14px; padding:10px 12px; background:color-mix(in srgb, var(--job-accent) 7%, rgba(255,255,255,.025)); border:1px solid color-mix(in srgb, var(--job-accent) 15%, rgba(148,163,184,.12)) }
.cron-next span,.cron-section-label { color:color-mix(in srgb, var(--job-accent) 32%, #94a3b8); font-size:10px; text-transform:uppercase; letter-spacing:.11em; font-weight:950 }
.cron-next b { color:#f4f8ff; font-size:15px; line-height:1.12 }
.cron-meta { display:flex; flex-wrap:wrap; gap:7px; color:#aebbd0; font-size:11px }
.cron-meta span { border:1px solid color-mix(in srgb, var(--job-accent) 12%, rgba(148,163,184,.13)); background:rgba(255,255,255,.022); border-radius:999px; padding:5px 7px }
.cron-disabled { display:grid; grid-column:1/-1; gap:10px; margin-top:2px; padding-top:12px; border-top:1px dashed rgba(148,163,184,.18) }
.cron-empty { color:var(--muted); padding:16px; text-align:center }
.grid { display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:16px }
.card { background:linear-gradient(180deg, rgba(18,26,41,.95), rgba(11,16,26,.95)); border:1px solid var(--line); border-radius:var(--radius); padding:20px; min-height:255px; display:flex; flex-direction:column; box-shadow:0 18px 48px rgba(0,0,0,.2); transition:transform .16s ease, border-color .16s ease }
.card:hover { transform:translateY(-2px); border-color:rgba(35,211,238,.45) }
.card-top { display:flex; justify-content:space-between; align-items:center; margin-bottom:18px }
.icon { font-size:24px; width:42px; height:42px; border-radius:14px; display:grid; place-items:center; background:rgba(255,255,255,.06); border:1px solid var(--line) }
.badge { color:#89f7d1; background:rgba(40,224,166,.09); border:1px solid rgba(40,224,166,.24); padding:6px 10px; border-radius:999px; font-size:12px; font-weight:800 }
.card h2 { font-size:20px; line-height:1.22; letter-spacing:-.025em; margin:0 0 10px }
.path { color:var(--muted); font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; line-height:1.45; word-break:break-word; margin:0 0 16px }
.meta { display:flex; flex-wrap:wrap; gap:8px; margin-top:auto; color:#aebbd0; font-size:12px }
.meta span { border:1px solid var(--line); background:rgba(255,255,255,.035); border-radius:999px; padding:6px 8px }
.actions { display:flex; gap:10px; margin-top:16px }
.primary,.secondary { border-radius:13px; padding:10px 12px; font-weight:800; font-size:13px; text-align:center }
.primary { flex:1; background:linear-gradient(135deg, var(--blue), var(--cyan)); color:white }
.secondary { border:1px solid var(--line); color:#c9d6e8; background:rgba(255,255,255,.04) }
.footer { color:var(--muted); font-size:12px; margin-top:26px; text-align:center }
@media (max-width:960px) { .grid { grid-template-columns:repeat(2, minmax(0,1fr)) } .stats { grid-template-columns:repeat(2, minmax(0,1fr)) } }
@media (max-width:640px) { .shell { width:min(1280px, calc(100% - 20px)); padding:14px 0 36px } .grid,.stats,.app-strip,.cron-panel { grid-template-columns:1fr } .hero { padding:16px 18px; border-radius:22px } .hero-row { gap:8px } h1 { font-size:clamp(27px, 8vw, 36px); margin:10px 0 0 } .hero-refresh { width:52px; height:52px; min-width:52px; min-height:52px; border-radius:20px } .hero-refresh:before { border-radius:18px } .hero-refresh-icon { font-size:29px } .cron-menu,.mobile-apps { border-radius:20px; margin-bottom:18px } .mobile-apps { padding:15px } .cron-menu summary { padding:15px; min-height:62px } .cron-panel { padding:0 8px 10px } .cron-item { padding:12px; border-radius:16px } .cron-item-top { flex-direction:column; align-items:flex-start } .cron-next b { font-size:14px } .cron-meta { flex-direction:column; align-items:flex-start } .actions { flex-direction:column } }
"""

HOME_DASHBOARD_JS = r"""
const DISK_METRIC_REFRESH_MS = 30 * 60 * 1000;
const refreshButton = document.querySelector('.hero-refresh');
function startMetricRefresh(paramName = 'refresh') {
  const url = new URL(window.location.href);
  url.searchParams.set(paramName, Date.now().toString());
  if (refreshButton) {
    refreshButton.classList.add('refreshing');
    refreshButton.setAttribute('aria-busy', 'true');
    refreshButton.setAttribute('aria-label', 'Refreshing Mac Studio LAN Portal metrics');
    refreshButton.setAttribute('title', 'Refreshing Mac Studio LAN Portal metrics');
    refreshButton.disabled = true;
  }
  window.requestAnimationFrame(() => window.setTimeout(() => window.location.replace(url.toString()), 90));
}
refreshButton?.addEventListener('click', () => startMetricRefresh('refresh'));
window.setTimeout(() => {
  startMetricRefresh('disk_metric_refresh');
}, DISK_METRIC_REFRESH_MS);
"""
