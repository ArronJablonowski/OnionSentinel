"""Late-bound Administration action and service orchestration."""
from __future__ import annotations

from typing import Any


def admin_action_state_sources(runtime: Any):
    return runtime.AdminActionStateSources(
        state_dir=runtime.ADMIN_STATE_DIR,
        lock_file=runtime.ADMIN_LOCK_FILE,
        actions=runtime.ADMIN_ACTIONS,
        process_running=runtime.process_is_running,
        now_iso=runtime.now_iso_local,
        parse_timestamp=runtime.parse_iso_timestamp,
        format_timestamp=runtime.format_iso_timestamp,
    )


def process_is_running(runtime: Any, pid: int | None) -> bool:
    if not pid:
        return False
    try:
        runtime.os.kill(pid, 0)
        return True
    except OSError:
        return False


def admin_status_path(runtime: Any, action_id: str):
    return runtime.action_status_path(action_id, runtime._admin_action_state_sources())


def admin_log_path(runtime: Any, action_id: str):
    return runtime.action_log_path(action_id, runtime._admin_action_state_sources())


def read_admin_action_status(runtime: Any, action_id: str) -> dict:
    return runtime.read_action_status(action_id, runtime._admin_action_state_sources())


def write_admin_action_status(runtime: Any, action_id: str, status: dict) -> None:
    runtime.write_action_status(action_id, status, runtime._admin_action_state_sources())


def latest_admin_action_outcome(runtime: Any) -> dict | None:
    return runtime.latest_action_outcome(runtime._admin_action_state_sources())


def read_admin_lock(runtime: Any) -> dict | None:
    return runtime.read_action_lock(runtime._admin_action_state_sources())


def running_admin_action(runtime: Any) -> dict | None:
    return runtime.running_action(runtime._admin_action_state_sources())


def claim_admin_action_lock(
    runtime: Any, action_id: str, label: str, started_at: str
) -> tuple[bool, str]:
    return runtime.claim_action_lock(
        action_id, label, started_at, runtime._admin_action_state_sources()
    )


def update_admin_action_lock_pid(runtime: Any, action_id: str, pid: int) -> None:
    runtime.update_action_lock_pid(
        action_id, pid, runtime._admin_action_state_sources()
    )


def release_admin_action_lock(runtime: Any, action_id: str) -> None:
    runtime.release_action_lock(action_id, runtime._admin_action_state_sources())


def start_admin_action(
    runtime: Any, action_id: str, confirmation: str = ""
) -> tuple[bool, str]:
    def spawn(wrapped_command: str, log: Any) -> int:
        proc = runtime.subprocess.Popen(
            ["/bin/bash", "-lc", wrapped_command],
            stdout=log,
            stderr=runtime.subprocess.STDOUT,
            stdin=runtime.subprocess.DEVNULL,
            cwd=str(runtime.HOME),
            env=runtime.ADMIN_COMMAND_ENV,
            start_new_session=True,
        )
        return proc.pid

    return runtime.run_admin_action(
        action_id,
        confirmation,
        runtime.AdminActionRunnerSources(
            actions=runtime.ADMIN_ACTIONS,
            state_dir=runtime.ADMIN_STATE_DIR,
            lock_file=runtime.ADMIN_LOCK_FILE,
            macos_update_checker=runtime.HOME
            / ".hermes"
            / "scripts"
            / "check_macos_updates.py",
            now_iso=runtime.now_iso_local,
            running_action=runtime.running_admin_action,
            read_status=runtime.read_admin_action_status,
            process_running=runtime.process_is_running,
            check_available=runtime.check_admin_action_available,
            claim_lock=runtime.claim_admin_action_lock,
            release_lock=runtime.release_admin_action_lock,
            update_lock_pid=runtime.update_admin_action_lock_pid,
            write_status=runtime.write_admin_action_status,
            status_path=runtime.admin_status_path,
            log_path=runtime.admin_log_path,
            quote=runtime.shlex.quote,
            spawn=spawn,
        ),
    )


def tail_file(runtime: Any, path: Any, max_chars: int = 7000) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return "No log output yet."
    if len(data) > max_chars:
        data = data[-max_chars:]
    return data.decode("utf-8", errors="replace")


def cron_failure_sources(runtime: Any):
    return runtime.CronFailureSources(
        jobs_file=runtime.CRON_JOBS_FILE,
        output_dir=runtime.CRON_OUTPUT_DIR,
        parse_timestamp=runtime.parse_iso_timestamp,
        format_timestamp=runtime.format_iso_timestamp,
        redact=runtime.redact_sensitive_text,
    )


def cron_failure_records(runtime: Any, limit: int = 12) -> list[dict]:
    return runtime.compose_cron_failure_records(
        runtime._cron_failure_sources(), limit=limit
    )


def render_cron_failure_log_section(runtime: Any) -> str:
    sources = runtime._cron_failure_sources()
    return runtime.render_cron_failure_log(
        runtime.compose_cron_failure_records(sources), sources
    )


def run_admin_version_command(
    runtime: Any, command: list[str], timeout: int = 12
) -> tuple[int | None, str]:
    try:
        proc = runtime.subprocess.run(
            command,
            text=True,
            stdout=runtime.subprocess.PIPE,
            stderr=runtime.subprocess.STDOUT,
            timeout=timeout,
            env=runtime.ADMIN_COMMAND_ENV,
        )
        return proc.returncode, proc.stdout.strip()
    except Exception as exc:
        return None, f"Unable to run {' '.join(command)}: {exc}"


def admin_action_version_info(runtime: Any, action_id: str) -> dict[str, str]:
    return runtime.compose_admin_action_version_info(
        action_id,
        runtime.AdminVersionSources(
            run_command=lambda command, timeout: runtime._run_admin_version_command(
                command, timeout=timeout
            ),
            read_macos_update_status=runtime.read_macos_update_status,
            hermes_bin=runtime.HERMES_BIN,
            hermes_project=runtime.HOME / ".hermes" / "hermes-agent",
        ),
    )


def check_admin_action_available(
    runtime: Any, action_id: str, skip_expensive: bool = False
) -> tuple[bool, str]:
    def run_command(
        command: list[str], timeout: int, combine_stderr: bool
    ) -> Any:
        try:
            proc = runtime.subprocess.run(
                command,
                text=True,
                stdout=runtime.subprocess.PIPE,
                stderr=(
                    runtime.subprocess.STDOUT
                    if combine_stderr
                    else runtime.subprocess.PIPE
                ),
                timeout=timeout,
                env=runtime.ADMIN_COMMAND_ENV,
            )
            return runtime.AdminCommandOutcome(
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr="" if combine_stderr else (proc.stderr or ""),
            )
        except Exception as exc:
            return runtime.AdminCommandOutcome(returncode=None, error=str(exc))

    return runtime.compose_admin_action_availability(
        action_id,
        skip_expensive,
        runtime.AdminAvailabilitySources(
            read_macos_update_status=runtime.read_macos_update_status,
            run_command=run_command,
            hermes_bin=runtime.HERMES_BIN,
        ),
    )


def admin_process_lines(runtime: Any) -> list[str]:
    proc = runtime.subprocess.run(
        ["/bin/ps", "axww", "-o", "pid=,args="],
        text=True,
        stdout=runtime.subprocess.PIPE,
        stderr=runtime.subprocess.PIPE,
        timeout=3,
        check=True,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def admin_service_probe_sources(runtime: Any):
    def docker_info() -> Any:
        docker_bin = runtime.shutil.which("docker") or "/usr/local/bin/docker"
        proc = runtime.subprocess.run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}"],
            text=True,
            stdout=runtime.subprocess.PIPE,
            stderr=runtime.subprocess.PIPE,
            timeout=4,
            check=False,
            env={
                **runtime.os.environ,
                "PATH": runtime.ADMIN_COMMAND_ENV.get(
                    "PATH", runtime.os.environ.get("PATH", "")
                ),
            },
        )
        return runtime.ServiceCommandOutcome(
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )

    return runtime.AdminServiceProbeSources(
        process_lines=runtime._admin_process_lines,
        docker_info=docker_info,
    )


def process_matches(
    runtime: Any, matchers: list[str], exclude: list[str] | None = None
) -> list[str]:
    return runtime.matching_process_lines(
        runtime._admin_process_lines(), matchers, exclude
    )


def macs_fan_control_status(runtime: Any) -> tuple[bool, str]:
    return runtime.probe_macs_fan_control_status(
        runtime._admin_service_probe_sources()
    )


def codex_app_status(runtime: Any) -> tuple[bool, str]:
    return runtime.probe_codex_app_status(runtime._admin_service_probe_sources())


def codex_cli_status(runtime: Any) -> tuple[bool, str]:
    return runtime.probe_codex_cli_status(runtime._admin_service_probe_sources())


def docker_status(runtime: Any) -> tuple[bool, str]:
    return runtime.probe_docker_status(runtime._admin_service_probe_sources())


def n8n_container_status(runtime: Any) -> dict[str, object]:
    docker_bin = runtime.shutil.which("docker") or "/usr/local/bin/docker"
    environment = {
        **runtime.os.environ,
        "PATH": runtime.ADMIN_COMMAND_ENV.get(
            "PATH", runtime.os.environ.get("PATH", "")
        ),
    }
    return runtime.compose_n8n_container_status(
        runtime.N8nContainerStatusSources(
            docker_bin=docker_bin,
            container_name=runtime.N8N_CONTAINER_NAME,
            health_url=runtime.N8N_HEALTH_URL,
            environment=environment,
            pipe=runtime.subprocess.PIPE,
            run=runtime.subprocess.run,
            now=lambda: runtime.dt.datetime.now().astimezone(),
            format_timestamp=runtime.format_iso_timestamp,
        )
    )


def admin_service_statuses(runtime: Any) -> dict[str, dict[str, object]]:
    checks = {
        "macs-fan-control": runtime.macs_fan_control_status,
        "codex": runtime.codex_app_status,
        "codex-cli": runtime.codex_cli_status,
        "docker": runtime.docker_status,
    }
    return runtime.compose_admin_service_statuses(
        runtime.ADMIN_SERVICE_LABELS, checks, runtime.n8n_container_status
    )


def start_admin_service(
    runtime: Any, service_id: str
) -> tuple[bool, str, dict[str, object] | None]:
    start_commands = {
        "macs-fan-control": ["/usr/bin/open", "-a", "Macs Fan Control"],
        "codex": ["/usr/bin/open", "-a", "Codex"],
        "codex-cli": [
            "/usr/bin/osascript", "-e",
            f'tell application "Terminal" to do script "{runtime.CODEX_CLI_BIN}"',
            "-e", 'tell application "Terminal" to activate',
        ],
        "docker": ["/usr/bin/open", "-a", "Docker"],
    }

    def spawn(command: list[str]) -> None:
        runtime.subprocess.Popen(
            command,
            stdout=runtime.subprocess.DEVNULL,
            stderr=runtime.subprocess.DEVNULL,
            start_new_session=True,
        )

    return runtime.start_allowed_admin_service(
        service_id,
        runtime.AdminServiceStartSources(
            labels=runtime.ADMIN_SERVICE_LABELS,
            start_commands=start_commands,
            statuses=runtime.admin_service_statuses,
            spawn=spawn,
        ),
    )


def defang_admin_service_json(
    runtime: Any, statuses: dict[str, dict[str, object]]
) -> dict[str, object]:
    return {"ok": True, "services": statuses, "time": runtime.now_iso_local()}
