"""Shared page registry and accessible navigation for Onion Sentinel."""
from __future__ import annotations

import html
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PageDefinition:
    key: str
    filename: str
    title: str
    subtitle: str


PAGES = (
    PageDefinition('home', 'home.html', 'Home', 'Executive SOC metrics and trends'),
    PageDefinition('alerts', 'index.html', 'SOC Alerts', 'AI-powered triage and investigation'),
    PageDefinition('investigations', 'investigations.html', 'Incident Responder', 'Incident response case work and analyst follow-up'),
    PageDefinition('cyber_threat_intel', 'cyber-threat-intel.html', 'Cyber Threat Intel', 'Threat intelligence briefs, indicators, and enrichment context'),
    PageDefinition('siem_engineering', 'siem-engineering.html', 'SIEM Engineer', 'Tuning recommendations and detection engineering workspace'),
    PageDefinition('threat_hunter', 'threat-hunter.html', 'Threat Hunter', 'Hunting workspace for suspicious patterns, pivots, and investigation leads'),
    PageDefinition('asset_inventory', 'asset-inventory.html', 'Asset Inventory', 'Current authoritative asset, hostname, and IP address mappings'),
    PageDefinition('software_inventory', 'software-inventory.html', 'Software Inventory', 'Endpoint-reported, network-observed, and inferred software evidence'),
    PageDefinition('system_health', 'system-health.html', 'System Health', 'n8n relay beacon history and gaps'),
    PageDefinition('ac_hunter', 'ac-hunter.html', 'AC Hunter Deep Review', 'Behavioral network findings correlated for analyst triage'),
    PageDefinition('reports', 'reports.html', 'Reports', 'Markdown reports and daily rollups'),
    PageDefinition('logs', 'logs.html', 'Onion Sentinel Logs', 'Application and service runtime logs'),
    PageDefinition('playbooks', 'playbooks.html', 'Playbooks', 'Response checklists and investigation paths'),
    PageDefinition('automations', 'automations.html', 'Automations', 'n8n workflow and relay automation status'),
    PageDefinition('sources', 'sources.html', 'Sources', 'Security Onion, relay, SQLite, and AI data sources'),
    PageDefinition('settings', 'settings.html', 'Settings', 'Dashboard and SOC workflow configuration'),
    PageDefinition('flow', 'flow.html', 'Flow', 'Resilient alert intake, evidence enrichment, and AI triage'),
)

PAGE_DEFS = [(page.key, page.filename, page.title, page.subtitle) for page in PAGES]
PAGE_BY_KEY = {
    page.key: {'filename': page.filename, 'title': page.title, 'subtitle': page.subtitle}
    for page in PAGES
}

NAV_ICONS = {
    'home': '<svg viewBox="0 0 24 24"><path d="M3.5 11.5 12 4l8.5 7.5"/><path d="M6 10.5V20h12v-9.5"/><path d="M10 20v-5h4v5"/></svg>',
    'system_health': '<svg viewBox="0 0 24 24"><path d="M3 12h4l2-5 4 10 2-5h6"/><circle cx="19" cy="12" r="1.6"/></svg>',
    'flow': '<svg viewBox="0 0 24 24"><path d="M3 7.5c1.7 1.4 3.4 1.4 5.1 0s3.4-1.4 5.1 0 3.4 1.4 5.1 0c.9-.7 1.8-1.1 2.7-1.1"/><path d="M3 12.5c1.7 1.4 3.4 1.4 5.1 0s3.4-1.4 5.1 0 3.4 1.4 5.1 0c.9-.7 1.8-1.1 2.7-1.1"/><path d="M3 17.5c1.7 1.4 3.4 1.4 5.1 0s3.4-1.4 5.1 0 3.4 1.4 5.1 0c.9-.7 1.8-1.1 2.7-1.1"/></svg>',
    'alerts': '<svg viewBox="0 0 24 24"><circle cx="6" cy="7" r="1.6"/><circle cx="6" cy="12" r="1.6"/><circle cx="6" cy="17" r="1.6"/><path d="M10 7h10M10 12h10M10 17h10"/></svg>',
    'threat_hunter': '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="6.5"/><circle cx="12" cy="12" r="2.4"/><path d="M12 3.5v3M12 17.5v3M3.5 12h3M17.5 12h3"/></svg>',
    'cyber_threat_intel': '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="7"/><path d="M12 5v14M5 12h14"/><path d="M7.5 7.5c2.6 1.4 6.4 1.4 9 0M7.5 16.5c2.6-1.4 6.4-1.4 9 0"/></svg>',
    'investigations': '<svg viewBox="0 0 24 24"><path d="M8 5H6.5A2.5 2.5 0 0 0 4 7.5v11A2.5 2.5 0 0 0 6.5 21h11a2.5 2.5 0 0 0 2.5-2.5v-11A2.5 2.5 0 0 0 17.5 5H16"/><path d="M9 3h6v4H9z"/><path d="M8 12h8M8 16h6"/></svg>',
    'asset_inventory': '<svg viewBox="0 0 24 24"><rect x="3.5" y="4" width="17" height="6" rx="2"/><rect x="3.5" y="14" width="17" height="6" rx="2"/><path d="M7 7h.01M7 17h.01M11 7h6M11 17h6"/></svg>',
    'software_inventory': '<svg viewBox="0 0 24 24"><path d="m12 3 8 4.5-8 4.5-8-4.5L12 3Z"/><path d="m4 12 8 4.5 8-4.5M4 16.5l8 4.5 8-4.5"/></svg>',
    'ac_hunter': '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4M11 7.5v7M7.5 11h7"/><circle cx="11" cy="11" r="2.2"/></svg>',
    'reports': '<svg viewBox="0 0 24 24"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><path d="M10.5 7.6 6.5 16.4M13.5 7.6l4 8.8M8 19h8"/></svg>',
    'logs': '<svg viewBox="0 0 24 24"><path d="M5 3.5h14v17H5z"/><path d="M8.5 8h7M8.5 12h7M8.5 16h4"/></svg>',
    'playbooks': '<svg viewBox="0 0 24 24"><path d="M4 20V11h4v9M10 20V5h4v15M16 20V8h4v12M3 20h18"/></svg>',
    'automations': '<svg viewBox="0 0 24 24"><path d="M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z"/><path d="M19.4 15a8 8 0 0 0 .1-1l2-1.5-2-3.5-2.4 1a7.8 7.8 0 0 0-1.7-1L15 6.5h-4L10.6 9a7.8 7.8 0 0 0-1.7 1l-2.4-1-2 3.5 2 1.5a8 8 0 0 0 .1 2l-2 1.5 2 3.5 2.4-1a7.8 7.8 0 0 0 1.7 1l.4 2.5h4l.4-2.5a7.8 7.8 0 0 0 1.7-1l2.4 1 2-3.5-2.2-1.5Z"/></svg>',
    'sources': '<svg viewBox="0 0 24 24"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/></svg>',
    'siem_engineering': '<svg viewBox="0 0 24 24"><path d="M4 6h7M15 6h5M4 12h4M12 12h8M4 18h10M18 18h2"/><circle cx="13" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="16" cy="18" r="2"/></svg>',
    'settings': '<svg viewBox="0 0 24 24"><path d="M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z"/><path d="M19.4 15a8 8 0 0 0 .1-1l2-1.5-2-3.5-2.4 1a7.8 7.8 0 0 0-1.7-1L15 6.5h-4L10.6 9a7.8 7.8 0 0 0-1.7 1l-2.4-1-2 3.5 2 1.5a8 8 0 0 0 .1 2l-2 1.5 2 3.5 2.4-1a7.8 7.8 0 0 0 1.7 1l.4 2.5h4l.4-2.5a7.8 7.8 0 0 0 1.7-1l2.4 1 2-3.5-2.2-1.5Z"/></svg>',
}


def build_nav_html(active_page: str, report_count: int, severity_class: str = 'none') -> str:
    if active_page not in PAGE_BY_KEY:
        raise ValueError(f'unknown dashboard page: {active_page}')
    safe_severity = re.sub(r'[^a-z0-9]+', '-', severity_class.lower()).strip('-') or 'informational'
    links = []
    for key, filename, title, _subtitle in PAGE_DEFS:
        active = ' active' if key == active_page else ''
        count = ''
        if key == 'alerts':
            count = (
                f'<span class="nav-count nav-count-sev-{html.escape(safe_severity)}" '
                f'id="soc-alerts-nav-count" data-severity="{html.escape(safe_severity)}">'
                f'{report_count}</span>'
            )
        links.append(
            f'<a class="nav-item{active}" href="{filename}" title="{html.escape(title)}" '
            f'aria-label="{html.escape(title)}"><span class="nav-left"><span class="nav-icon" '
            f'aria-hidden="true">{NAV_ICONS[key]}</span><span class="nav-label">'
            f'{html.escape(title)}</span></span>{count}</a>'
        )
    return '<nav class="nav">' + ''.join(links) + '</nav>'


def placeholder_page_section(page_key: str) -> str:
    if page_key not in PAGE_BY_KEY:
        raise ValueError(f'unknown dashboard page: {page_key}')
    page = PAGE_BY_KEY[page_key]
    title = html.escape(page['title'])
    subtitle = html.escape(page['subtitle'])
    return f'''
    <section class="view-section active placeholder-view" aria-label="{title}">
      <div class="empty">
        <h2>{title}</h2>
        <p>{subtitle}</p>
        <p>This page now has its own route. Data-backed widgets can be added here without changing the SOC Alerts table page.</p>
      </div>
    </section>'''
