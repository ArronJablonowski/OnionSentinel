"""Pure composition of Onion Sentinel's generated static page routes.

This module deliberately knows nothing about SQLite, runtime directories, or
publication.  Callers provide an already-rendered shell, navigation, page
content, and the alert-page client contracts that must be present.
"""
from __future__ import annotations

import html
import re
from dataclasses import dataclass


OVERVIEW_MARKER = (
    '<section id="overview-view" class="view-section overview-view" '
    'aria-label="SOC Alerts overview">'
)
ALERTS_MARKER = (
    '<section id="alerts-view" class="view-section alerts-view" '
    'aria-label="SOC alert table">'
)
ACTIVE_ALERTS_MARKER = (
    '<section id="alerts-view" class="view-section alerts-view active" '
    'aria-label="SOC alert table">'
)


@dataclass(frozen=True)
class StaticPagePlan:
    """All route-specific values needed to transform one dashboard shell."""

    page_key: str
    title: str
    subtitle: str
    navigation_html: str
    content_html: str | None = None
    alert_contracts: tuple[str, ...] = ()


def remove_between_markers(text: str, start_marker: str, end_marker: str) -> str:
    """Remove a bounded shell section while preserving malformed input."""
    start = text.find(start_marker)
    end = text.find(end_marker, start)
    if start == -1 or end == -1:
        return text
    return text[:start] + text[end:]


def replace_main_page_content(text: str, replacement: str) -> str:
    """Replace the shell's primary sections without touching its footer."""
    content_start = text.find('<section id="overview-view"')
    if content_start == -1:
        content_start = text.find('<section id="alerts-view"')
    footer_start = text.find('<div class="footer">', content_start)
    if footer_start == -1:
        footer_start = text.find('<div class="footer"', content_start)
    if content_start == -1 or footer_start == -1:
        return text
    return text[:content_start] + replacement + text[footer_start:]


def compose_static_page(shell_html: str, plan: StaticPagePlan) -> str:
    """Apply a deterministic, side-effect-free page plan to a shell."""
    data_view = 'alerts' if plan.page_key == 'alerts' else 'overview'
    rendered = shell_html.replace(
        "dashboard-metrics.css?v=20260712-responsive-qa",
        "dashboard-metrics.css?v=20260717-pre-soak-qa",
    )
    rendered = re.sub(
        r'<title>.*?</title>',
        f'<title>{html.escape(plan.title)} - Onion Sentinel</title>',
        rendered,
        count=1,
    )
    rendered = rendered.replace(
        '<div class="app-shell" data-view="overview">',
        f'<div class="app-shell" data-view="{data_view}">',
        1,
    )
    rendered = re.sub(
        r'<nav class="nav">.*?</nav>',
        plan.navigation_html,
        rendered,
        count=1,
        flags=re.S,
    )
    rendered = rendered.replace(
        '<div class="health" id="system-health-tile" data-health-state="unknown">',
        '<a class="health system-health-link" id="system-health-tile" '
        'data-health-state="unknown" href="system-health.html" '
        'style="display:block;text-decoration:none">',
        1,
    )
    rendered = rendered.replace(
        '</span></div><div class="analyst byline">',
        '</span></a><div class="analyst byline">',
        1,
    )
    rendered = rendered.replace(
        '<h1 id="page-title">SOC Overview</h1>',
        f'<h1 id="page-title">{html.escape(plan.title)}</h1>',
        1,
    )
    rendered = rendered.replace(
        '<div id="page-subtitle" class="subtitle">Resilient alert intake, '
        'evidence enrichment, and AI triage</div>',
        f'<div id="page-subtitle" class="subtitle">'
        f'{html.escape(plan.subtitle)}</div>',
        1,
    )
    rendered = rendered.replace(
        "setView(appShell?.dataset.view||'overview');",
        '/* static page navigation is rendered server-side */',
    )

    if plan.page_key == 'alerts':
        rendered = remove_between_markers(
            rendered, OVERVIEW_MARKER, ALERTS_MARKER
        ).replace(ALERTS_MARKER, ACTIVE_ALERTS_MARKER, 1)
        for contract in plan.alert_contracts:
            if contract and contract not in rendered:
                rendered = rendered.replace('</body>', contract + '</body>', 1)
        return rendered

    if plan.content_html is None:
        raise ValueError(f'missing static page content: {plan.page_key}')
    return replace_main_page_content(rendered, plan.content_html)
