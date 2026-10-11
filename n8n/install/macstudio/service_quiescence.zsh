# Sourced by install-macstudio-stack.zsh; retain the caller shell and traps.
critical_launch_agents_down() {
  local plist
  local label
  for plist in \
    com.arron.soc.alert-store.plist \
    com.arron.soc.ai-analysis.plist \
    com.arron.soc.ai-analysis-cli.plist \
    com.arron.soc.dhcp-asset-discovery.plist \
    com.arron.soc.endpoint-software-inventory.plist \
    com.arron.soc.software-inventory.plist \
    com.arron.soc.ac-hunter.plist \
    com.arron.onion-sentinel.evaluation-artifact-maintenance.plist \
    com.arron.onion-sentinel.application-log-maintenance.plist
  do
    launchctl unload "$LAUNCHD_DIR/$plist" >/dev/null 2>&1 || true
  done
  for label in \
    com.arron.soc.alert-store \
    com.arron.soc.ai-analysis \
    com.arron.soc.ai-analysis-cli \
    com.arron.soc.dhcp-asset-discovery \
    com.arron.soc.endpoint-software-inventory \
    com.arron.soc.software-inventory \
    com.arron.soc.ac-hunter \
    com.arron.onion-sentinel.evaluation-artifact-maintenance \
    com.arron.onion-sentinel.application-log-maintenance
  do
    launchctl bootout "gui/$(id -u)/$label" >/dev/null 2>&1 || true
  done
  # A worker can be inside a model subprocess when launchd is unloaded. On
  # macOS that subprocess may be reparented to PID 1 and continue consuming a
  # prompt even though its Python owner and durable lease are gone. Stop only
  # the two exact AI runtime entry points and Codex subprocesses carrying the
  # runner-owned isolated-workspace marker. Durable leases recover interrupted
  # work; allowing old code to finish after a wire-contract cutover would
  # produce an incorrectly attributed analysis.
  local runtime_ai_pids
  local runtime_codex_pids
  runtime_ai_pids="$(
    /bin/ps -axo pid=,command= \
      | /usr/bin/awk \
        -v scheduler="$STACK_DIR/bin/auto-run-ai-analysis.py" \
        -v runner="$STACK_DIR/bin/run-local-ai-analysis.py" \
        '$2 ~ /[Pp]ython/ && (index($0, scheduler) || index($0, runner)) {print $1}'
  )"
  if [[ -n "$runtime_ai_pids" ]]; then
    for pid in ${(f)runtime_ai_pids}; do
      kill -TERM "$pid" >/dev/null 2>&1 || true
    done
  fi
  runtime_codex_pids="$(
    /bin/ps -axo pid=,command= \
      | /usr/bin/awk '
        $2 ~ /(^|\/)codex$/ \
        && index($0, "/onion-sentinel-codex-") \
        && index($0, "codex exec") \
        && index($0, "--ignore-user-config") \
        && index($0, "--ignore-rules") {print $1}'
  )"
  if [[ -n "$runtime_codex_pids" ]]; then
    for pid in ${(f)runtime_codex_pids}; do
      kill -TERM "$pid" >/dev/null 2>&1 || true
    done
  fi
  if [[ -n "$runtime_ai_pids" || -n "$runtime_codex_pids" ]]; then
    for attempt in {1..10}; do
      runtime_ai_pids="$(
        /bin/ps -axo pid=,command= \
          | /usr/bin/awk \
            -v scheduler="$STACK_DIR/bin/auto-run-ai-analysis.py" \
            -v runner="$STACK_DIR/bin/run-local-ai-analysis.py" \
            '$2 ~ /[Pp]ython/ && (index($0, scheduler) || index($0, runner)) {print $1}'
      )"
      runtime_codex_pids="$(
        /bin/ps -axo pid=,command= \
          | /usr/bin/awk '
            $2 ~ /(^|\/)codex$/ \
            && index($0, "/onion-sentinel-codex-") \
            && index($0, "codex exec") \
            && index($0, "--ignore-user-config") \
            && index($0, "--ignore-rules") {print $1}'
      )"
      [[ -z "$runtime_ai_pids" && -z "$runtime_codex_pids" ]] && break
      /bin/sleep 1
    done
  fi
}

critical_launch_agents_are_down() {
  local label
  for label in \
    com.arron.soc.alert-store \
    com.arron.soc.ai-analysis \
    com.arron.soc.ai-analysis-cli \
    com.arron.soc.dhcp-asset-discovery \
    com.arron.soc.endpoint-software-inventory \
    com.arron.soc.software-inventory \
    com.arron.soc.ac-hunter
  do
    if launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1; then
      return 1
    fi
  done
  if /bin/ps -axo pid=,command= \
    | /usr/bin/awk \
      -v scheduler="$STACK_DIR/bin/auto-run-ai-analysis.py" \
      -v runner="$STACK_DIR/bin/run-local-ai-analysis.py" \
      '$2 ~ /[Pp]ython/ && (index($0, scheduler) || index($0, runner)) {found=1} END {exit !found}'
  then
    return 1
  fi
  if /bin/ps -axo pid=,command= \
    | /usr/bin/awk '
      $2 ~ /(^|\/)codex$/ \
      && index($0, "/onion-sentinel-codex-") \
      && index($0, "codex exec") \
      && index($0, "--ignore-user-config") \
      && index($0, "--ignore-rules") {found=1} END {exit !found}'
  then
    return 1
  fi
  return 0
}

keep_critical_agents_down_on_failure() {
  local exit_code=$?
  if (( exit_code != 0 )); then
    critical_launch_agents_down
    echo "Install failed; alert-store and both AI LaunchAgents remain stopped." >&2
    echo "The DHCP asset-discovery LaunchAgent also remains stopped." >&2
    echo "The software-inventory LaunchAgent also remains stopped." >&2
  fi
  release_ai_deployment_guard
  cleanup_alert_store_stage
  return $exit_code
}
