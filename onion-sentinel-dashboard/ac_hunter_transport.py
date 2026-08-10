"""Relay-only transport and in-memory AC Hunter authentication client."""
from __future__ import annotations

from ac_hunter_config import *  # noqa: F401,F403
from ac_hunter_config import _dependency, _safe_error  # noqa: F401
def _relay_diagnostic(stdout: object, stderr: object) -> str:
    """Return only broker-authored, non-sensitive diagnostics."""

    message = ""
    try:
        value = json.loads(str(stdout or ""))
    except (TypeError, json.JSONDecodeError):
        value = None
    if isinstance(value, dict):
        message = _safe_error(value.get("error"), "")
    if not message:
        message = _safe_error(stderr, "")
    return message or "the forced AC Hunter Relay request failed"


class RelayTransport:
    """One fixed forced-command SSH transport to 10.88.8.8."""

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        runner: Optional[Callable[..., Any]] = None,
        contract: Optional[ModuleType] = None,
    ) -> None:
        self.config = dict(config)
        self.contract = contract or _dependency("ac_hunter_contract")
        if runner is None:
            runner = _dependency("bounded_process").run_bounded_command
        self.runner = runner

    def command(self) -> List[str]:
        return [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"UserKnownHostsFile={self.config['known_hosts']}",
            "-o",
            f"ConnectTimeout={self.config['connect_timeout_seconds']}",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "RequestTTY=no",
            "-o",
            "LogLevel=ERROR",
            "-i",
            str(self.config["ssh_key"]),
            "-p",
            str(self.config["relay_port"]),
            f"{FIXED_RELAY_USER}@{FIXED_RELAY_HOST}",
        ]

    def call(
        self,
        operation: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        request_id = self.contract.new_request_id()
        request = {
            "contract": self.contract.CONTRACT,
            "request_id": request_id,
            "operation": operation,
            "params": dict(params or {}),
            "headers": dict(headers or {}),
            "body": dict(body or {}),
        }
        # Compile locally as well as on the Relay.  This ensures a caller can
        # never turn a named operation into a URL, hostname, method, or path.
        self.contract.compile_request(request)
        stdin_text = json.dumps(request, separators=(",", ":"), sort_keys=True)
        completed = self.runner(
            self.command(),
            stdin_text=stdin_text,
            timeout_seconds=float(self.config["timeout_seconds"]),
            max_stdout_bytes=int(self.config["max_response_bytes"]),
            max_stderr_bytes=int(self.config["max_stderr_bytes"]),
        )
        try:
            value = json.loads(str(completed.stdout or ""))
            response = self.contract.validate_relay_response(value, request_id)
        except Exception as exc:
            raise AcHunterTransportError(
                "the forced AC Hunter Relay returned an invalid response"
            ) from exc
        if completed.returncode != 0 and int(response.get("status", 0)) == 0:
            raise AcHunterTransportError(
                _relay_diagnostic(completed.stdout, completed.stderr)
            )
        return response


class _CsrfParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.token = ""

    def handle_starttag(
        self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]
    ) -> None:
        if tag.lower() != "input" or self.token:
            return
        values = {key.lower(): value or "" for key, value in attrs}
        if values.get("name") == "csrf_token":
            self.token = values.get("value", "")[:1024]


class AcHunterApiClient:
    """Stateful cookie/JWT client whose only I/O path is RelayTransport."""

    def __init__(
        self,
        transport: Any,
        credentials_loader: Callable[[], Tuple[str, str]],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.transport = transport
        self.credentials_loader = credentials_loader
        self.clock = clock
        self._cookies: Dict[str, str] = {}
        self._jwt = ""
        self._jwt_expiry = 0.0
        self._auth_lock = threading.RLock()

    def _cookie_header(self) -> str:
        return "; ".join(
            f"{name}={value}" for name, value in sorted(self._cookies.items())
        )

    def _accept_cookies(self, response: Mapping[str, Any]) -> None:
        response_headers = response.get("headers")
        if not isinstance(response_headers, dict):
            return
        raw_values = response_headers.get("set_cookie", [])
        if not isinstance(raw_values, list):
            return
        for raw in raw_values:
            if not isinstance(raw, str):
                continue
            parsed = SimpleCookie()
            try:
                parsed.load(raw)
            except Exception:
                continue
            for name, morsel in parsed.items():
                if (
                    re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
                    and len(morsel.value.encode("utf-8")) <= 4096
                    and not any(
                        character in morsel.value
                        for character in ("\r", "\n", "\x00", ";")
                    )
                ):
                    if morsel.value:
                        self._cookies[name] = morsel.value
                    else:
                        self._cookies.pop(name, None)
        if len(self._cookies) > 16:
            self._cookies = dict(sorted(self._cookies.items())[:16])

    @staticmethod
    def _token_expiry(token: str) -> float:
        parts = token.split(".")
        if len(parts) != 3:
            raise AcHunterAuthenticationError("AC Hunter returned an invalid JWT")
        encoded = parts[1] + "=" * (-len(parts[1]) % 4)
        try:
            payload = json.loads(
                base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8")
            )
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AcHunterAuthenticationError(
                "AC Hunter returned an invalid JWT"
            ) from exc
        expiry = payload.get("exp") if isinstance(payload, dict) else None
        if isinstance(expiry, bool) or not isinstance(expiry, (int, float)):
            raise AcHunterAuthenticationError("AC Hunter JWT has no valid expiry")
        return float(expiry)

    @staticmethod
    def _success(
        response: Mapping[str, Any],
        statuses: Iterable[int] = (200,),
    ) -> bool:
        return response.get("ok") is True and response.get("status") in set(statuses)

    def _authenticate(self) -> None:
        with self._auth_lock:
            if (
                self._jwt
                and self._jwt_expiry
                > self.clock() + JWT_REFRESH_SKEW_SECONDS
            ):
                return
            self._jwt = ""
            self._jwt_expiry = 0.0
            self._cookies.clear()

            form = self.transport.call("login_form")
            self._accept_cookies(form)
            if not self._success(form):
                raise AcHunterAuthenticationError(
                    "AC Hunter login form was unavailable"
                )
            parser = _CsrfParser()
            raw_html = form.get("body")
            if isinstance(raw_html, str):
                try:
                    parser.feed(raw_html)
                except Exception:
                    parser.token = ""

            email, password = self.credentials_loader()
            login_headers: Dict[str, str] = {}
            cookie = self._cookie_header()
            if cookie:
                login_headers["cookie"] = cookie
            login = self.transport.call(
                "login",
                headers=login_headers,
                body={
                    "email": email,
                    "password": password,
                    "csrf_token": parser.token,
                    "next": "/jwt/json",
                    "remember": False,
                },
            )
            # Drop the only local references to the credential strings as soon
            # as the bounded relay invocation has returned.
            del email
            del password
            self._accept_cookies(login)
            if not self._success(login, (302, 303)):
                raise AcHunterAuthenticationError(
                    "AC Hunter service-account login failed"
                )

            jwt_headers: Dict[str, str] = {}
            cookie = self._cookie_header()
            if cookie:
                jwt_headers["cookie"] = cookie
            token_response = self.transport.call("jwt", headers=jwt_headers)
            self._accept_cookies(token_response)
            if not self._success(token_response):
                raise AcHunterAuthenticationError(
                    "AC Hunter JWT issuance failed"
                )
            payload = token_response.get("body")
            token = payload.get("token") if isinstance(payload, dict) else None
            if (
                not isinstance(token, str)
                or not 16 <= len(token) <= 16384
                or not re.fullmatch(r"[A-Za-z0-9._~-]+", token)
            ):
                raise AcHunterAuthenticationError(
                    "AC Hunter JWT issuance returned an invalid token"
                )
            expiry = self._token_expiry(token)
            now = self.clock()
            if expiry <= now + 10 or expiry > now + 15 * 60:
                raise AcHunterAuthenticationError(
                    "AC Hunter JWT expiry is outside the expected window"
                )
            self._jwt = token
            self._jwt_expiry = expiry

    def invalidate_authentication(self) -> None:
        with self._auth_lock:
            self._jwt = ""
            self._jwt_expiry = 0.0
            self._cookies.clear()

    def get(
        self,
        operation: str,
        params: Optional[Mapping[str, Any]] = None,
    ) -> object:
        for attempt in range(2):
            self._authenticate()
            headers = {"authorization": f"Bearer {self._jwt}"}
            cookie = self._cookie_header()
            if cookie:
                headers["cookie"] = cookie
            response = self.transport.call(
                operation,
                params=params or {},
                headers=headers,
            )
            self._accept_cookies(response)
            status = response.get("status")
            if status in {302, 401, 403}:
                self.invalidate_authentication()
                if attempt == 0:
                    continue
                raise AcHunterAuthenticationError(
                    "AC Hunter authentication expired during collection"
                )
            if response.get("ok") is not True or status != 200:
                raise AcHunterTransportError(
                    _safe_error(
                        response.get("error"),
                        f"AC Hunter {operation} request failed",
                    )
                )
            return response.get("body")
        raise AcHunterAuthenticationError(
            "AC Hunter authentication could not be refreshed"
        )
