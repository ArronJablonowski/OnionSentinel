"""Ollama benchmark aggregation and human-readable reporting."""
from __future__ import annotations

import statistics
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any


def ns_to_seconds(value: Any) -> float:
    try:
        return float(value or 0) / 1_000_000_000
    except (TypeError, ValueError):
        return 0.0


def _collect_batches(
    model: str,
    cases: Sequence[Any],
    query_cases: Sequence[Any],
    args: Any,
    run_decisions: Callable[..., dict[str, Any]],
    score_decisions: Callable[..., dict[str, Any]],
    run_queries: Callable[..., dict[str, Any]],
    score_queries: Callable[..., dict[str, Any]],
) -> list[dict[str, Any]]:
    batches: list[dict[str, Any]] = []
    categories = sorted({case.category for case in cases})
    for repetition in range(1, args.repetitions + 1):
        for category in categories:
            category_cases = [case for case in cases if case.category == category]
            print(
                f"  {model}: {category} repetition "
                f"{repetition}/{args.repetitions}",
                flush=True,
            )
            run = run_decisions(
                args.ollama_url,
                model,
                category_cases,
                repetition,
                args.timeout,
                args.retries,
                args.temperature,
            )
            batches.append({
                "category": category,
                "repetition": repetition,
                "run": run,
                "score": score_decisions(category_cases, run),
            })
        print(
            f"  {model}: query_generation repetition "
            f"{repetition}/{args.repetitions}",
            flush=True,
        )
        query_run = run_queries(
            args.ollama_url,
            model,
            query_cases,
            repetition,
            args.timeout,
            args.retries,
            args.temperature,
        )
        batches.append({
            "category": "query_generation",
            "repetition": repetition,
            "run": query_run,
            "score": score_queries(query_cases, query_run),
        })
    return batches


def _category_scores(
    categories: Sequence[str],
    batches: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    scores: dict[str, dict[str, Any]] = {}
    for category in (*categories, "query_generation"):
        selected = [batch for batch in batches if batch["category"] == category]
        points = sum(batch["score"]["points"] for batch in selected)
        possible = sum(batch["score"]["possible"] for batch in selected)
        scores[category] = {
            "points": points,
            "possible": possible,
            "percent": round(100 * points / possible, 2) if possible else 0.0,
        }
    return scores


def _performance(batches: list[dict[str, Any]]) -> dict[str, Any]:
    successful = [batch for batch in batches if batch["run"].get("ok")]
    wall = [
        float(batch["run"].get("wall_seconds") or 0)
        for batch in successful
    ]
    eval_tokens = sum(
        int(batch["run"]["ollama_metrics"].get("eval_count") or 0)
        for batch in successful
    )
    eval_seconds = sum(
        ns_to_seconds(batch["run"]["ollama_metrics"].get("eval_duration"))
        for batch in successful
    )
    return {
        "successful_batches": len(successful),
        "wall_seconds_total": round(sum(wall), 3),
        "wall_seconds_median": round(statistics.median(wall), 3) if wall else None,
        "generation_tokens_per_second": (
            round(eval_tokens / eval_seconds, 2) if eval_seconds else None
        ),
    }


def benchmark_model(
    model: str,
    cases: Sequence[Any],
    query_cases: Sequence[Any],
    args: Any,
    *,
    run_decisions: Callable[..., dict[str, Any]],
    score_decisions: Callable[..., dict[str, Any]],
    run_queries: Callable[..., dict[str, Any]],
    score_queries: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    categories = sorted({case.category for case in cases})
    batches = _collect_batches(
        model,
        cases,
        query_cases,
        args,
        run_decisions,
        score_decisions,
        run_queries,
        score_queries,
    )
    points = sum(batch["score"]["points"] for batch in batches)
    possible = sum(batch["score"]["possible"] for batch in batches)
    return {
        "model": model,
        "points": points,
        "possible": possible,
        "percent": round(100 * points / possible, 2) if possible else 0.0,
        "category_scores": _category_scores(categories, batches),
        **_performance(batches),
        "total_batches": len(batches),
        "batches": batches,
    }


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    models = sorted(
        payload["models"],
        key=lambda item: (-item["percent"], item["wall_seconds_total"]),
    )
    categories = sorted({
        key for item in models for key in item["category_scores"]
    })
    lines = [
        "# Onion Sentinel Local Model Benchmark",
        "",
        f"Generated: {payload['generated_at']}",
        (
            f"Cases: {payload['case_count']} synthetic cases "
            f"({payload.get('decision_case_count', payload['case_count'])} "
            f"decisions; {payload.get('query_case_count', 0)} generated queries); "
            f"repetitions: {payload['repetitions']}"
        ),
        "",
        "| Model | Overall | " + " | ".join(categories)
        + " | Wall time | tok/s |",
        "| :--- | ---: | " + " | ".join("---:" for _ in categories)
        + " | ---: | ---: |",
    ]
    for item in models:
        category_values = [
            f"{item['category_scores'][category]['percent']:.1f}%"
            for category in categories
        ]
        lines.append(
            "| " + " | ".join([
                item["model"],
                f"{item['percent']:.1f}%",
                *category_values,
                f"{item['wall_seconds_total']:.1f}s",
                str(item["generation_tokens_per_second"] or "n/a"),
            ]) + " |"
        )
    lines.extend([
        "",
        (
            "Decision scoring: answer 2 points; required evidence 1; "
            "case-scoped citations 1; rationale present 1."
        ),
        (
            "Query scoring: output present 1; language 1; required fields 1; "
            "read-only safety 1; valid bounded syntax 1."
        ),
        (
            "Fixtures use reserved addresses and example domains only. "
            "No live alert data is read."
        ),
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")
