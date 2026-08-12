"""SIEM engineering page composition and recommendation projection."""
from __future__ import annotations

from dashboard_builder_contract import *  # noqa: F403
from dashboard_builder_settings import *  # noqa: F403
from dashboard_builder_report_core import *  # noqa: F403
from dashboard_builder_reports import *  # noqa: F403


def siem_engineering_html_list(values: object, empty: str) -> str:
    return render_siem_engineering_html_list(values, empty)


def _siem_recommendation_view(report: AlertReport) -> SiemRecommendationViewModel:
    analysis = report.ai_analysis if isinstance(report.ai_analysis, dict) else {}
    response = analysis.get('response') if isinstance(analysis.get('response'), dict) else {}
    normalize = lambda value: normalize_iso_display_text(value)
    return SiemRecommendationViewModel(
        title=report.title, digest=report.digest, rel_source=report.rel_source,
        summary=normalize(report.summary), ai_summary=normalize(ai_summary_for(report)),
        criticality=report.criticality, criticality_rank=report.criticality_rank,
        alert_source=report.alert_source, source_ip=report.source_ip,
        destination_ip=report.destination_ip, destination_port=report.destination_port,
        source_endpoint=report.source_endpoint, destination_endpoint=report.destination_endpoint,
        rule_id=report.rule_id, rule_name=report.rule_name,
        raw_alert_count=report.raw_alert_count, total_seen_count=report.total_seen_count,
        repeat_count=report.repeat_count, first_seen=normalize(report.first_seen),
        last_seen=last_seen_iso_for(report), alert_group_key=report.alert_group_key,
        alert_ts=report.alert_ts, ai_status_key=report.ai_status_key,
        ai_status_label=report.ai_status_label, ai_status_detail=normalize(report.ai_status_detail),
        enrichment_status_label=report.enrichment_status_label,
        enrichment_status_detail=normalize(report.enrichment_status_detail),
        enrichment_record_count=report.enrichment_record_count,
        enrichment_skip_count=report.enrichment_skip_count,
        enrichment_error_count=report.enrichment_error_count,
        pcap_status_label=report.pcap_status_label,
        pcap_status_detail=normalize(report.pcap_status_detail),
        tuning_recommendation=report.tuning_recommendation,
        tuning_reason=normalize(report.tuning_reason),
        recommended_tuning_actions=tuple(normalize(action) for action in report.recommended_tuning_actions),
        generated_at=normalize(analysis.get('generated_at') or 'n/a'), response=response,
    )


def siem_engineering_detail_report(report: AlertReport, recommendation_kind: str) -> str:
    return render_siem_engineering_detail_report(
        _siem_recommendation_view(report), recommendation_kind
    )


def siem_engineering_tuning_row(report: AlertReport, index: int) -> str:
    return render_siem_engineering_tuning_row(_siem_recommendation_view(report), index)


def siem_engineering_detection_row(report: AlertReport, index: int) -> str:
    return render_siem_engineering_detection_row(_siem_recommendation_view(report), index)


def siem_engineering_roi_score(report: AlertReport) -> tuple[int, int, int, float]:
    return render_siem_engineering_roi_score(_siem_recommendation_view(report))


def siem_engineering_best_roi_section(reports: list[AlertReport]) -> str:
    views = tuple(_siem_recommendation_view(report) for report in reports)
    return render_siem_engineering_best_roi(views)


def siem_engineering_table(title: str, subtitle: str, rows: str, empty: str) -> str:
    return render_siem_engineering_table(title, rows, empty)


def __siem_actionable_reports(
    reports: list[AlertReport],
) -> list[AlertReport]:
    return [
        report for report in reports
        if report.tuning_recommendation
        and report.tuning_recommendation not in {'none', 'n/a', 'needs_more_data'}
    ]


def __siem_repeated_reports(
    reports: list[AlertReport], actionable: list[AlertReport],
) -> list[AlertReport]:
    return sorted(
        [report for report in reports if report.repeat_count >= 3 and report not in actionable],
        key=lambda report: (report.repeat_count, report.criticality_rank), reverse=True,
    )[:4]


def __siem_engineering_page_view(
    reports: list[AlertReport],
    settings: dict[str, object],
    actionable: list[AlertReport],
    repeated: list[AlertReport],
) -> SiemEngineeringPageViewModel:
    return SiemEngineeringPageViewModel(
        mode=str(settings.get('mode', 'ollama')),
        local_model=str(settings.get('ollama_model') or current_local_ai_model()),
        cloud_model=str(settings.get('cloud_model') or settings.get('cloud_provider') or 'not configured'),
        analyzed=sum(1 for report in reports if report.ai_status_key == 'analyzed'),
        total=len(reports),
        all_candidates=tuple(_siem_recommendation_view(report) for report in reports),
        actionable=tuple(_siem_recommendation_view(report) for report in actionable),
        repeated=tuple(_siem_recommendation_view(report) for report in repeated),
    )


def siem_engineering_page_section(reports: list[AlertReport]) -> str:
    settings = load_soc_ai_settings()
    actionable = __siem_actionable_reports(reports)
    repeated = __siem_repeated_reports(reports, actionable)
    view = __siem_engineering_page_view(
        reports, settings, actionable, repeated
    )
    return render_siem_engineering_page(view)
