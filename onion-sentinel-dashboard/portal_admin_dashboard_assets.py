"""Static Administration dashboard CSS and browser behavior."""

ADMIN_DASHBOARD_STYLE = r"""<style>
.admin-status-grid { display:grid; grid-template-columns:repeat(5, minmax(0,1fr)); gap:14px; margin:18px 0 }
.admin-indicator { --indicator-accent:#28e0a6; position:relative; border:1px solid color-mix(in srgb, var(--indicator-accent) 28%, rgba(148,163,184,.16)); border-radius:22px; padding:18px; background:linear-gradient(145deg, color-mix(in srgb, var(--indicator-accent) 10%, rgba(18,26,41,.94)), rgba(10,16,27,.90)); box-shadow:0 14px 40px rgba(0,0,0,.18) }
.admin-indicator.warn { --indicator-accent:#f8c76a }
.admin-indicator.alert { --indicator-accent:#ff7a90 }
.admin-indicator-top { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; margin-bottom:7px }
.admin-indicator span { display:block; color:color-mix(in srgb, var(--indicator-accent) 50%, #9bdff2); font-size:10px; letter-spacing:.13em; text-transform:uppercase; font-weight:950 }
.service-start-button { flex:0 0 auto; border:1px solid color-mix(in srgb, var(--indicator-accent) 38%, rgba(255,255,255,.18)); border-radius:999px; padding:7px 10px; color:#061018; background:linear-gradient(135deg, var(--indicator-accent), #23d3ee); font-size:11px; font-weight:950; cursor:pointer; box-shadow:0 10px 24px rgba(0,0,0,.16) }
.service-start-button:disabled { cursor:wait; opacity:.55; filter:saturate(.55); color:#dbeafe; background:linear-gradient(135deg, #64748b, #334155) }
.admin-indicator strong { display:block; color:#f8fbff; font-size:clamp(24px,3.4vw,40px); line-height:1; letter-spacing:-.05em }
.admin-indicator small { display:block; margin-top:8px; color:#aebbd0; font-size:12px; line-height:1.4; overflow-wrap:anywhere }
.admin-grid { display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:14px; margin:18px 0 }
.admin-card { position:relative; overflow:hidden; border:1px solid color-mix(in srgb, var(--admin-accent) 26%, rgba(148,163,184,.16)); border-radius:22px; background:linear-gradient(145deg, color-mix(in srgb, var(--admin-accent) 10%, rgba(18,26,41,.94)), rgba(10,16,27,.90)); padding:18px; box-shadow:0 14px 40px rgba(0,0,0,.18) }
.admin-card:before { content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, var(--admin-accent), rgba(148,163,184,.32)) }
.admin-card-top { display:flex; align-items:flex-start; justify-content:space-between; gap:12px }
.admin-card h2 { margin:0 0 10px }
.admin-action-metric { margin:14px 0; border:1px solid color-mix(in srgb, var(--admin-accent) 24%, rgba(148,163,184,.14)); border-radius:18px; padding:14px 15px; background:linear-gradient(135deg, color-mix(in srgb, var(--admin-accent) 10%, rgba(15,23,42,.88)), rgba(2,6,23,.36)); box-shadow:inset 0 1px 0 rgba(255,255,255,.045) }
.admin-action-metric span { display:block; color:color-mix(in srgb, var(--admin-accent) 46%, #9bdff2); font-size:10px; letter-spacing:.13em; text-transform:uppercase; font-weight:950; margin-bottom:6px }
.admin-action-metric strong { display:block; color:#f8fbff; font-size:clamp(24px,3.4vw,40px); line-height:1; letter-spacing:-.06em }
.admin-action-metric small { display:block; margin-top:7px; color:#aebbd0; font-size:12px; line-height:1.35; overflow-wrap:anywhere }
.admin-version-grid { display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:10px; margin:14px 0 }
.admin-version-metric { min-width:0; border:1px solid color-mix(in srgb, var(--admin-accent) 18%, rgba(148,163,184,.14)); border-radius:16px; padding:12px; background:rgba(2,6,23,.30) }
.admin-version-metric.latest { background:linear-gradient(135deg, color-mix(in srgb, var(--admin-accent) 9%, rgba(2,6,23,.42)), rgba(2,6,23,.30)) }
.admin-version-metric span { display:block; color:color-mix(in srgb, var(--admin-accent) 44%, #9bdff2); font-size:10px; letter-spacing:.12em; text-transform:uppercase; font-weight:950; margin-bottom:6px }
.admin-version-metric strong { display:block; color:#edf5ff; font-size:13px; line-height:1.28; overflow-wrap:anywhere }
.admin-card form { display:grid; gap:10px; margin-top:14px }
.confirm-label { display:grid; gap:7px; color:#d7e5f8; font-size:13px; font-weight:800 }
.confirm-label input { width:100%; border:1px solid rgba(255,122,144,.38); border-radius:14px; padding:11px 12px; color:#fff; background:rgba(2,6,23,.62); font:inherit }
.admin-button { border:0; border-radius:14px; padding:12px 14px; font-weight:950; color:#061018; background:linear-gradient(135deg, var(--admin-accent), #23d3ee); cursor:pointer }
.admin-button:disabled { cursor:not-allowed; opacity:.48; filter:saturate(.45); background:linear-gradient(135deg, #64748b, #334155); color:#dbeafe }
.admin-button.danger { color:#fff; background:linear-gradient(135deg, #ff7a90, #dc2626) }
.admin-button.danger:disabled { background:linear-gradient(135deg, #64748b, #334155); color:#dbeafe }
.admin-logout-form { margin:0; flex:0 0 auto }
.admin-logout-button { border:1px solid rgba(35,211,238,.32); border-radius:999px; padding:9px 12px; color:#aeeeff; background:rgba(35,211,238,.065); font-weight:950; cursor:pointer }
.admin-logout-button:hover { border-color:rgba(35,211,238,.62); background:rgba(35,211,238,.12) }
.cron-menu { --cron-accent:#7dd3fc; --cron-accent2:#94a3b8; position:relative; margin:18px 0; border:1px solid color-mix(in srgb, var(--cron-accent) 24%, rgba(148,163,184,.16)); border-radius:24px; background:linear-gradient(145deg, color-mix(in srgb, var(--cron-accent) 8%, rgba(18,26,41,.94)), rgba(10,15,25,.91) 62%, color-mix(in srgb, var(--cron-accent2) 7%, rgba(8,12,20,.92))); box-shadow:0 16px 44px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.045); overflow:hidden; isolation:isolate }
.cron-menu:before { content:""; position:absolute; inset:0 0 auto 0; height:4px; background:linear-gradient(90deg, color-mix(in srgb, var(--cron-accent) 72%, #64748b), color-mix(in srgb, var(--cron-accent2) 72%, #475569)); opacity:.62 }
.cron-menu summary { min-height:68px; list-style:none; cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:14px; padding:17px 18px 16px; touch-action:manipulation }
.cron-menu summary::-webkit-details-marker { display:none }
.cron-summary-main { display:flex; align-items:center; gap:12px; min-width:0 }
.cron-summary-main b { display:block; color:#eef6ff; font-size:18px; line-height:1.05; letter-spacing:-.025em }
.cron-summary-main small { display:block; margin-top:5px; color:color-mix(in srgb, var(--cron-accent) 36%, #94a3b8); font-size:11px; font-weight:900; letter-spacing:.1em; text-transform:uppercase }
.cron-dot { width:12px; height:12px; border-radius:999px; background:color-mix(in srgb, var(--green, #28e0a6) 70%, #94a3b8); box-shadow:0 0 18px rgba(40,224,166,.38); flex:0 0 auto }
.cron-chevron { color:#c8d6ea; font-size:24px; line-height:1; transition:transform .16s ease, color .16s ease }
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
.cron-empty { color:var(--muted, #8b98ac); padding:16px; text-align:center }
.cron-failure-log table code { white-space:normal; word-break:break-word }
.cron-failure-detail { margin-top:12px; border:1px solid rgba(248,199,106,.22); border-radius:16px; background:rgba(248,199,106,.045); overflow:hidden }
.cron-failure-detail summary { cursor:pointer; padding:12px 14px; color:#ffdfa3; font-weight:900; line-height:1.35 }
.cron-failure-detail pre { margin:0; border-top:1px solid rgba(248,199,106,.16); border-radius:0; max-height:460px; overflow:auto }
@media (max-width:900px) { .admin-grid { grid-template-columns:1fr } .admin-status-grid { grid-template-columns:1fr } .cron-panel { grid-template-columns:1fr } }
</style>
"""

ADMIN_DASHBOARD_SCRIPT_TEMPLATE = r"""<script>
const adminServiceToken = __TOKEN_JSON__;
function updateServiceCard(service) {
  const card = document.querySelector(`[data-service-card="${service.id}"]`);
  if (!card) return;
  const level = service.level || (service.running ? 'ok' : 'warn');
  const startable = service.startable !== false;
  card.dataset.running = service.running ? 'true' : 'false';
  card.dataset.level = level;
  card.classList.toggle('ok', level === 'ok');
  card.classList.toggle('warn', level !== 'ok' && level !== 'alert');
  card.classList.toggle('alert', level === 'alert');
  const value = card.querySelector('strong');
  const detail = card.querySelector('small');
  const top = card.querySelector('.admin-indicator-top');
  if (value) value.textContent = service.value || (service.running ? 'Running' : 'Not running');
  if (detail) detail.textContent = service.detail || '';
  const existing = card.querySelector('[data-start-service]');
  if (service.running || !startable) {
    if (existing) existing.remove();
  } else if (!existing && top) {
    const button = document.createElement('button');
    button.className = 'service-start-button';
    button.type = 'button';
    button.dataset.startService = service.id;
    button.textContent = 'Start';
    top.appendChild(button);
  } else if (existing) {
    existing.disabled = false;
    existing.textContent = 'Start';
  }
}
async function refreshServiceStatuses() {
  const response = await fetch('/api/admin/service-status', {cache: 'no-store', credentials: 'same-origin'});
  if (!response.ok) throw new Error(`Status check failed: ${response.status}`);
  const data = await response.json();
  Object.values(data.services || {}).forEach(updateServiceCard);
  return data.services || {};
}
async function pollServiceUntilRunning(serviceId, button) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const services = await refreshServiceStatuses();
    if (services[serviceId] && services[serviceId].running) return true;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  if (button && document.body.contains(button)) {
    button.disabled = false;
    button.textContent = 'Start';
  }
  return false;
}
document.addEventListener('click', async (event) => {
  const button = event.target.closest('[data-start-service]');
  if (!button) return;
  event.preventDefault();
  const serviceId = button.dataset.startService;
  button.disabled = true;
  button.textContent = 'Starting…';
  try {
    const response = await fetch('/api/admin/start-service', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin',
      body: JSON.stringify({token: adminServiceToken, service: serviceId})
    });
    const data = await response.json().catch(() => ({ok:false, error:'Invalid JSON response'}));
    if (data.service) updateServiceCard(data.service);
    if (!response.ok || !data.ok) throw new Error(data.error || data.message || `Start failed: ${response.status}`);
    button.textContent = 'Checking…';
    await pollServiceUntilRunning(serviceId, button);
  } catch (error) {
    const card = document.querySelector(`[data-service-card="${serviceId}"]`);
    const detail = card ? card.querySelector('small') : null;
    if (detail) detail.textContent = `WARNING: ${error.message}`;
    if (button && document.body.contains(button)) {
      button.disabled = false;
      button.textContent = 'Start';
    }
  }
});
document.querySelectorAll('form[data-reboot-form="true"]').forEach((form) => {
  form.addEventListener('submit', (event) => {
    const input = form.querySelector('input[name="confirmation"]');
    if (!input || input.value !== 'REBOOT') {
      event.preventDefault();
      alert('Type REBOOT to confirm before rebooting.');
      return;
    }
    if (!confirm('Reboot this Mac now? This will interrupt running tasks.')) {
      event.preventDefault();
    }
  });
});
const adminActionRunning = __ACTION_RUNNING__;
if (adminActionRunning) {
  setTimeout(() => window.location.reload(), 5000);
}
</script>
"""
