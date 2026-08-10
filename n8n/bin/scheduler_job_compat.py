"""Durable claim, reporting, prompt, and runner compatibility policy."""
from __future__ import annotations

from pathlib import Path
from typing import Any, MutableMapping


RuntimeNamespace = MutableMapping[str, Any]


def report_ai_job_status(
    runtime: RuntimeNamespace,
    base_url: str,
    group_id: str,
    status: str,
    error: str = "",
    lease_token: str = "",
    job_type: str = "ai_analysis",
    retryable: bool = True,
    expected_job_id: int = 0,
    expected_representative_alert_id: str = "",
    expected_dispatch_id: str = "",
    expected_stable_group_key: str = "",
    expected_assigned_route: str = "",
    expected_reviewer_route: str = "",
    reviewer_required: bool = False,
) -> bool | str:
    return runtime["transition_ai_job_status"](
        runtime["scheduler_reporting_sources"](),
        base_url,
        group_id,
        status,
        error,
        lease_token,
        job_type,
        retryable,
        expected_job_id,
        expected_representative_alert_id,
        expected_dispatch_id,
        expected_stable_group_key,
        expected_assigned_route,
        expected_reviewer_route,
        reviewer_required,
    )


def job_reanalysis_attempt_id(
    runtime: RuntimeNamespace,
    job_payload: dict[str, Any],
    lease_token: str,
) -> str:
    if job_payload.get("manual_reanalysis") is not True:
        return ""
    run_id = str(job_payload.get("reanalysis_run_id") or "").strip().lower()
    case_id = str(job_payload.get("case_id") or "").strip().lower()
    if not runtime["re"].fullmatch(r"irr-[a-f0-9-]{36}", run_id):
        return ""
    if not runtime["re"].fullmatch(r"ir-[a-z0-9_-]{1,64}", case_id):
        return ""
    return runtime["incident_reanalysis_attempt_id"](lease_token)


def ai_failure_is_retryable(markers: tuple[str, ...], error: object) -> bool:
    detail = str(error or "").strip().lower()
    return not any(marker in detail for marker in markers)


def reconcile_completed_ai_jobs(
    runtime: RuntimeNamespace,
    base_url: str,
    group_ids: set[str],
) -> int:
    if not group_ids:
        return 0
    payload = runtime["json"].dumps(
        {"job_type": "ai_analysis", "dedupe_keys": sorted(group_ids)}
    ).encode("utf-8")
    request = runtime["urllib"].request.Request(
        f"{base_url.rstrip('/')}/jobs/reconcile-completed",
        data=payload,
        headers=runtime["alert_store_mutation_headers"](),
        method="POST",
    )
    try:
        with runtime["urllib"].request.urlopen(request, timeout=15) as response:
            if response.status not in range(200, 300):
                raise RuntimeError(
                    f"AI job reconciliation returned HTTP {response.status}"
                )
            result = runtime["read_bounded_json"](
                response,
                max_bytes=runtime["DEFAULT_MAX_CONTROL_RESPONSE_BYTES"],
            )
            return int(result.get("reconciled") or 0)
    except runtime["urllib"].error.HTTPError as exc:
        if exc.code == 404:
            return 0
        raise RuntimeError(
            f"AI job reconciliation returned HTTP {exc.code}"
        ) from exc
    except (
        runtime["urllib"].error.URLError,
        runtime["BoundedHttpError"],
    ) as exc:
        raise RuntimeError(f"AI job reconciliation failed: {exc}") from exc


def claimed_durable_ai_job(
    runtime: RuntimeNamespace,
    processing_transition: object,
    database_path: Path,
    *,
    expected_job_type: str,
    expected_group_id: str,
    expected_job_id: int = 0,
) -> tuple[dict[str, object], str, str, str]:
    return runtime["load_claimed_durable_job"](
        runtime["ClaimSnapshotPolicy"](
            severity_priority=runtime["SEVERITY_PRIORITY"],
            stable_group_key_valid=runtime[
                "valid_controlled_stable_group_key"
            ],
        ),
        processing_transition,
        database_path,
        expected_job_type=expected_job_type,
        expected_group_id=expected_group_id,
        expected_job_id=expected_job_id,
    )


def require_controlled_claim_identity(
    runtime: RuntimeNamespace,
    args: Any,
    claimed_payload: dict[str, object],
    *,
    claimed_alert_id: str,
    claimed_group_id: str,
    claimed_job_id: int,
    expected_job_id: int,
) -> None:
    runtime["require_controlled_lease_identity"](
        runtime["ControlledLeaseIdentitySources"](
            stable_group_key_valid=runtime[
                "valid_controlled_stable_group_key"
            ],
            require_release=runtime["require_controlled_release_attestation"],
            route_contract=lambda payload: runtime[
                "controlled_job_route_contract"
            ](args, payload),
            reject=runtime["ControlledClaimRejected"],
        ),
        args,
        claimed_payload,
        claimed_alert_id=claimed_alert_id,
        claimed_group_id=claimed_group_id,
        claimed_job_id=claimed_job_id,
        expected_job_id=expected_job_id,
    )


def strict_ai_settings_module(runtime: RuntimeNamespace) -> Any:
    cached = runtime.get("_STRICT_AI_SETTINGS_MODULE")
    if cached is not None:
        return cached
    runner_path = (
        runtime["BIN_DIR"] / "run-local-ai-analysis.py"
    ).resolve(strict=True)
    module_name = (
        "_onion_sentinel_strict_ai_settings_"
        + runtime["hashlib"].sha256(
            str(runner_path).encode("utf-8")
        ).hexdigest()[:16]
    )
    module = runtime["sys"].modules.get(module_name)
    if module is None:
        spec = runtime["importlib"].util.spec_from_file_location(
            module_name,
            runner_path,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("analysis runner settings loader is unavailable")
        module = runtime["importlib"].util.module_from_spec(spec)
        runtime["sys"].modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            runtime["sys"].modules.pop(module_name, None)
            raise
    if not callable(getattr(module, "load_ai_settings", None)) or not callable(
        getattr(module, "enabled_agent_model_routes", None)
    ):
        raise RuntimeError("analysis runner settings loader is incomplete")
    runtime["_STRICT_AI_SETTINGS_MODULE"] = module
    return module


def strict_controlled_ai_settings(
    runtime: RuntimeNamespace,
    settings_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], set[str]]:
    runner = runtime["_strict_ai_settings_module"]()
    return runtime["strict_controlled_ai_settings"](
        settings_path,
        runtime["MAX_AI_SETTINGS_BYTES"],
        runtime["StrictSettingsSources"](
            load_ai_settings=runner.load_ai_settings,
            read_bytes_bounded=runner.read_bytes_bounded,
            enabled_agent_model_routes=runner.enabled_agent_model_routes,
            max_settings_bytes=runner.DEFAULT_MAX_SETTINGS_BYTES,
        ),
    )


def controlled_job_route_contract(
    runtime: RuntimeNamespace,
    args: Any,
    job_payload: dict[str, object],
) -> dict[str, object]:
    settings_path = Path(
        getattr(args, "ai_settings_file", runtime["DEFAULT_AI_SETTINGS"])
    )
    return runtime["validate_job_route_contract"](
        runtime["ControlledRoutePolicy"](
            model_route_pattern=runtime["CONTROLLED_MODEL_ROUTE_RE"]
        ),
        runtime["ControlledRouteSources"](
            load_settings=lambda: runtime["_strict_controlled_ai_settings"](
                settings_path
            ),
            reject=runtime["ControlledClaimRejected"],
            settings_errors=(
                OSError,
                UnicodeError,
                ValueError,
                TypeError,
                RuntimeError,
            ),
        ),
        job_payload,
    )


def controlled_claim_expectations(
    runtime: RuntimeNamespace,
    args: Any,
    selected: Any,
    job_payload: dict[str, object],
) -> dict[str, object]:
    return runtime["validate_claim_expectations"](
        runtime["ControlledClaimSources"](
            stable_group_key_valid=runtime[
                "valid_controlled_stable_group_key"
            ],
            require_release=runtime["require_controlled_release_attestation"],
            route_contract=lambda payload: runtime[
                "controlled_job_route_contract"
            ](args, payload),
            reject=runtime["ControlledClaimRejected"],
        ),
        args,
        selected,
        job_payload,
    )


def run_command(
    runtime: RuntimeNamespace,
    cmd: list[str],
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    env: dict[str, str] | None,
    progress_callback: Any,
    progress_interval_seconds: float,
) -> Any:
    runtime.get("print", print)("running:", " ".join(cmd), flush=True)
    return runtime["run_bounded_command"](
        cmd,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        env=env,
        progress_callback=progress_callback,
        progress_interval_seconds=progress_interval_seconds,
    )


def collect_incident_evidence(
    runtime: RuntimeNamespace,
    alert_id: str,
    args: Any,
    *,
    progress_callback: Any = None,
) -> Path:
    collector = Path(runtime["__file__"]).with_name(
        "collect-incident-evidence.py"
    )
    proc = runtime["run_command"](
        [
            runtime["sys"].executable,
            str(collector),
            "--alert-id",
            alert_id,
            "--db",
            str(args.db),
            "--config",
            str(args.incident_evidence_config),
            "--out-dir",
            str(args.incident_evidence_dir),
        ],
        timeout_seconds=360,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=runtime["DEFAULT_MAX_CHILD_STDERR_BYTES"],
        progress_callback=progress_callback,
        progress_interval_seconds=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            proc.stderr.strip()
            or f"incident evidence collector failed rc={proc.returncode}"
        )
    output_lines = [
        line.strip() for line in proc.stdout.splitlines() if line.strip()
    ]
    if not output_lines:
        raise RuntimeError("incident evidence collector returned no artifact path")
    artifact = Path(output_lines[-1])
    try:
        artifact.resolve().relative_to(args.incident_evidence_dir.resolve())
    except ValueError as exc:
        raise RuntimeError(
            "incident evidence collector returned a path outside its configured directory"
        ) from exc
    if not artifact.is_file():
        raise RuntimeError("incident evidence collector did not publish its artifact")
    return artifact


def build_prompt(
    runtime: RuntimeNamespace,
    alert_id: str,
    args: Any,
    job_payload: dict[str, object] | None = None,
    incident_evidence_path: Path | None = None,
) -> Path:
    return runtime["build_prompt_package"](
        runtime["PromptBuilderDefaults"](
            builder_path=Path(runtime["__file__"]).with_name(
                "build-ai-investigation-prompt.py"
            ),
            python_executable=runtime["sys"].executable,
            database=runtime["DEFAULT_DB"],
            rollup_dir=runtime["DEFAULT_ROLLUP_DIR"],
            agent_memory_dir=runtime["DEFAULT_AGENT_MEMORY_DIR"],
            shared_memory_file=runtime["DEFAULT_SHARED_MEMORY_FILE"],
            pcap_analysis_dir=runtime["DEFAULT_PCAP_ANALYSIS_DIR"],
            prior_analysis_dir=runtime["DEFAULT_ANALYSIS_DIR"],
            asset_inventory_file=runtime["DEFAULT_ASSET_INVENTORY_FILE"],
            detection_playbooks=runtime["DEFAULT_DETECTION_PLAYBOOKS"],
            investigation_skills=runtime["DEFAULT_INVESTIGATION_SKILLS"],
            timeout_seconds=180,
            max_stdout_bytes=1024 * 1024,
            max_stderr_bytes=runtime["DEFAULT_MAX_CHILD_STDERR_BYTES"],
        ),
        runtime["PromptBuilderSources"](
            initial_prompt_limit=runtime[
                "effective_initial_prompt_package_limit"
            ],
            role_prompt_file=runtime["role_prompt_file"],
            role_second_opinion_prompt_file=runtime[
                "role_second_opinion_prompt_file"
            ],
            role_memory_file=runtime["role_memory_file"],
            run_command=runtime["run_command"],
            emit_stderr=lambda message: runtime.get("print", print)(
                message,
                file=runtime["sys"].stderr,
                end="",
            ),
        ),
        alert_id,
        args,
        job_payload,
        incident_evidence_path,
    )


def runner_invocation_defaults(runtime: RuntimeNamespace) -> Any:
    return runtime["RunnerInvocationDefaults"](
        python_executable=runtime["sys"].executable,
        runner_path=Path(runtime["__file__"]).with_name(
            "run-local-ai-analysis.py"
        ),
        prompt_dir=runtime["DEFAULT_PROMPT_DIR"],
        harness_policy=runtime["DEFAULT_INVESTIGATION_HARNESS_POLICY"],
        disagreement_prompt=runtime[
            "DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT"
        ],
        live_osquery_config=runtime["DEFAULT_LIVE_OSQUERY_CONFIG"],
        incident_evidence_config=runtime["DEFAULT_INCIDENT_EVIDENCE_CONFIG"],
        investigation_pivot_dir=runtime["DEFAULT_INVESTIGATION_PIVOT_DIR"],
        max_stdout_bytes=runtime["DEFAULT_MAX_CHILD_STDOUT_BYTES"],
        max_stderr_bytes=runtime["DEFAULT_MAX_CHILD_STDERR_BYTES"],
        token_environment_key=runtime["CONTROLLED_EVALUATION_TOKEN_ENV"],
        token_pattern=runtime["CONTROLLED_EVALUATION_TOKEN_RE"],
    )


def analysis_command(
    runtime: RuntimeNamespace,
    prompt_path: Path,
    args: Any,
    *,
    reanalysis_attempt_id: str = "",
    agent_role: str = "",
) -> list[str]:
    return runtime["build_analysis_command"](
        runtime["runner_invocation_defaults"](),
        runtime["runner_invocation_sources"](),
        prompt_path,
        args,
        reanalysis_attempt_id=reanalysis_attempt_id,
        agent_role=agent_role,
    )


def run_analysis(
    runtime: RuntimeNamespace,
    prompt_path: Path,
    args: Any,
    *,
    progress_callback: Any = None,
    reanalysis_attempt_id: str = "",
    agent_role: str = "",
    controlled_result_identity: dict[str, object] | None = None,
) -> Any:
    return runtime["invoke_analysis_runner"](
        runtime["runner_invocation_defaults"](),
        runtime["runner_invocation_sources"](),
        prompt_path,
        args,
        progress_callback=progress_callback,
        reanalysis_attempt_id=reanalysis_attempt_id,
        agent_role=agent_role,
        controlled_result_identity=controlled_result_identity,
    )
