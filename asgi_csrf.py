from http.cookies import SimpleCookie
from collections.abc import Awaitable, Callable, Container, Mapping, MutableMapping
from enum import IntEnum
from functools import wraps
from multipart import FormParser
import os
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl
from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous import BadSignature
import secrets

if TYPE_CHECKING:
    Scope = MutableMapping[str, Any]
    Message = MutableMapping[str, Any]
    Receive = Callable[[], Awaitable[Message]]
    Send = Callable[[Message], Awaitable[None]]
    ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

DEFAULT_COOKIE_NAME = "csrftoken"
DEFAULT_COOKIE_PATH = "/"
DEFAULT_COOKIE_DOMAIN = None
DEFAULT_COOKIE_SECURE = False
DEFAULT_COOKIE_SAMESITE = "Lax"
DEFAULT_FORM_INPUT = "csrftoken"
DEFAULT_HTTP_HEADER = "x-csrftoken"
DEFAULT_SIGNING_NAMESPACE = "csrftoken"
SCOPE_KEY = "csrftoken"
ENV_SECRET = "ASGI_CSRF_SECRET"



class Errors(IntEnum):
    FORM_URLENCODED_MISMATCH = 1
    MULTIPART_MISMATCH = 2
    FILE_BEFORE_TOKEN = 3
    UNKNOWN_CONTENT_TYPE = 4


error_messages = {
    Errors.FORM_URLENCODED_MISMATCH: "form-urlencoded POST field did not match cookie",
    Errors.MULTIPART_MISMATCH: "multipart/form-data POST field did not match cookie",
    Errors.FILE_BEFORE_TOKEN: "File encountered before csrftoken - make sure csrftoken is first in the HTML",
    Errors.UNKNOWN_CONTENT_TYPE: "Unknown content-type",
}


def asgi_csrf_decorator(
    cookie_name: str = DEFAULT_COOKIE_NAME,
    http_header: str = DEFAULT_HTTP_HEADER,
    form_input: str = DEFAULT_FORM_INPUT,
    signing_secret: Optional[str] = None,
    signing_namespace: str = DEFAULT_SIGNING_NAMESPACE,
    always_protect: Optional[Container[str]] = None,
    always_set_cookie: bool = False,
    skip_if_scope: Optional[Callable[["Scope"], bool]] = None,
    cookie_path: str = DEFAULT_COOKIE_PATH,
    cookie_domain: Optional[str] = DEFAULT_COOKIE_DOMAIN,
    cookie_secure: bool = DEFAULT_COOKIE_SECURE,
    cookie_samesite: str = DEFAULT_COOKIE_SAMESITE,
    send_csrf_failed: Optional[Callable[["Scope", "Send", int], Awaitable[None]]] = None,
) -> Callable[["ASGIApp"], "ASGIApp"]:
    send_csrf_failed = send_csrf_failed or default_send_csrf_failed
    if signing_secret is None:
        signing_secret = os.environ.get(ENV_SECRET, None)
    if signing_secret is None:
        signing_secret = make_secret(128)
    signer = URLSafeSerializer(signing_secret)

    def _asgi_csrf_decorator(app: "ASGIApp") -> "ASGIApp":
        @wraps(app)
        async def app_wrapped_with_csrf(scope: "Scope", receive: "Receive", send: "Send") -> None:
            if scope["type"] != "http":
                await app(scope, receive, send)
                return
            cookies = cookies_from_scope(scope)
            csrftoken = None
            has_csrftoken_cookie = False
            should_set_cookie = False
            page_needs_vary_header = False
            if cookie_name in cookies:
                try:
                    csrftoken = cookies.get(cookie_name, "")
                    signer.loads(csrftoken, signing_namespace)
                except BadSignature:
                    csrftoken = ""
                else:
                    has_csrftoken_cookie = True
            else:
                if always_set_cookie:
                    should_set_cookie = True

            if not has_csrftoken_cookie:
                csrftoken = signer.dumps(make_secret(16), signing_namespace)

            def get_csrftoken() -> Optional[str]:
                nonlocal should_set_cookie
                nonlocal page_needs_vary_header
                page_needs_vary_header = True
                if not has_csrftoken_cookie:
                    should_set_cookie = True
                return csrftoken

            scope = {**scope, **{SCOPE_KEY: get_csrftoken}}

            async def wrapped_send(event: "Message") -> None:
                if event["type"] == "http.response.start":
                    original_headers = event.get("headers") or []
                    new_headers = []
                    if page_needs_vary_header:
                        # Loop through original headers, modify or add "vary"
                        found_vary = False
                        for key, value in original_headers:
                            if key == b"vary":
                                found_vary = True
                                vary_bits = [v.strip() for v in value.split(b",")]
                                if b"Cookie" not in vary_bits:
                                    vary_bits.append(b"Cookie")
                                value = b", ".join(vary_bits)
                            new_headers.append((key, value))
                        if not found_vary:
                            new_headers.append((b"vary", b"Cookie"))
                    else:
                        new_headers = original_headers
                    if should_set_cookie:
                        cookie_attrs = [
                            "{}={}".format(cookie_name, csrftoken),
                            "Path={}".format(cookie_path),
                            "SameSite={}".format(cookie_samesite),
                        ]

                        if cookie_domain is not None:
                            cookie_attrs.append("Domain={}".format(cookie_domain))

                        if cookie_secure:
                            cookie_attrs.append("Secure")

                        new_headers.append(
                            (
                                b"set-cookie",
                                "; ".join(cookie_attrs).encode("utf-8"),
                            )
                        )
                    event = {
                        "type": "http.response.start",
                        "status": event["status"],
                        "headers": new_headers,
                    }
                await send(event)

            # Apply to anything that isn't GET, HEAD, OPTIONS, TRACE (like Django does)
            if scope["method"] in {"GET", "HEAD", "OPTIONS", "TRACE"}:
                await app(scope, receive, wrapped_send)
            else:
                # Check for CSRF token in various places
                headers = dict(scope.get("headers") or [])
                if secrets.compare_digest(
                    headers.get(http_header.encode("latin-1"), b"").decode("latin-1"),
                    csrftoken,
                ):
                    # x-csrftoken header matches
                    await app(scope, receive, wrapped_send)
                    return
                # If no cookies, skip check UNLESS path is in always_protect
                if not headers.get(b"cookie"):
                    if always_protect is None or scope["path"] not in always_protect:
                        await app(scope, receive, wrapped_send)
                        return
                # Skip CSRF if skip_if_scope tells us to
                if skip_if_scope and skip_if_scope(scope):
                    await app(scope, receive, wrapped_send)
                    return
                # Authorization: Bearer skips CSRF check
                if (
                    headers.get(b"authorization", b"")
                    .decode("latin-1")
                    .startswith("Bearer ")
                ):
                    await app(scope, receive, wrapped_send)
                    return
                # We need to look for it in the POST body
                content_type = headers.get(b"content-type", b"").split(b";", 1)[0]
                if content_type == b"application/x-www-form-urlencoded":
                    # Consume entire POST body and check for csrftoken field
                    post_data, replay_receive = await _parse_form_urlencoded(receive)
                    if secrets.compare_digest(post_data.get(form_input, ""), csrftoken):
                        # All is good! Forward on the request and replay the body
                        await app(scope, replay_receive, wrapped_send)
                        return
                    else:
                        await send_csrf_failed(
                            scope, wrapped_send, Errors.FORM_URLENCODED_MISMATCH
                        )
                        return
                elif content_type == b"multipart/form-data":
                    # Consume non-file items until we see a csrftoken
                    # If we see a file item first, it's an error
                    boundary = headers.get(b"content-type").split(b"; boundary=")[1]
                    assert boundary is not None, "missing 'boundary' header: {}".format(
                        repr(headers)
                    )
                    # Consume enough POST body to find the csrftoken, or error if form seen first
                    try:
                        (
                            csrftoken_from_body,
                            replay_receive,
                        ) = await _parse_multipart_form_data(boundary, receive)
                        if not secrets.compare_digest(
                            csrftoken_from_body or "", csrftoken
                        ):
                            await send_csrf_failed(
                                scope,
                                wrapped_send,
                                Errors.MULTIPART_MISMATCH,
                            )
                            return
                    except FileBeforeToken:
                        await send_csrf_failed(
                            scope,
                            wrapped_send,
                            Errors.FILE_BEFORE_TOKEN,
                        )
                        return
                    # Now replay the body
                    await app(scope, replay_receive, wrapped_send)
                    return
                else:
                    await send_csrf_failed(
                        scope, wrapped_send, Errors.UNKNOWN_CONTENT_TYPE
                    )
                    return

        return app_wrapped_with_csrf

    return _asgi_csrf_decorator


async def _parse_form_urlencoded(receive: "Receive") -> Tuple[Dict[str, str], "Receive"]:
    # Returns {key: value}, replay_receive
    # where replay_receive is an awaitable that can replay what was received
    # We ignore cases like foo=one&foo=two because we do not need to
    # handle that case for our single csrftoken= argument
    body = b""
    more_body = True
    messages = []
    while more_body:
        message = await receive()
        assert message["type"] == "http.request", message
        messages.append(message)
        body += message.get("body", b"")
        more_body = message.get("more_body", False)

    async def replay_receive() -> "Message":
        if messages:
            return messages.pop(0)
        else:
            return await receive()

    return dict(parse_qsl(body.decode("utf-8"))), replay_receive


class NoToken(Exception):
    pass


class TokenFound(Exception):
    pass


class FileBeforeToken(Exception):
    pass


async def _parse_multipart_form_data(boundary: bytes, receive: "Receive") -> Tuple[Optional[str], "Receive"]:
    # Returns (csrftoken, replay_receive) - or raises an exception
    csrftoken = None

    def on_field(field):
        if field.field_name == b"csrftoken":
            csrftoken = field.value.decode("utf-8")
            raise TokenFound(csrftoken)

    class ErrorOnWrite:
        def __init__(self, file_name: bytes | None, field_name: bytes | None, config: Mapping[str, Any]) -> None:
            pass

        def write(self, data: bytes) -> int:
            raise FileBeforeToken

    body = b""
    more_body = True
    messages: List["Message"] = []

    async def replay_receive() -> "Message":
        if messages:
            return messages.pop(0)
        else:
            return await receive()

    form_parser = FormParser(
        "multipart/form-data",
        on_field,
        lambda: None,
        boundary=boundary,
        FileClass=ErrorOnWrite,
    )
    try:
        while more_body:
            message = await receive()
            assert message["type"] == "http.request", message
            messages.append(message)
            form_parser.write(message.get("body", b""))
            more_body = message.get("more_body", False)
    except TokenFound as t:
        return t.args[0], replay_receive

    return None, replay_receive


async def default_send_csrf_failed(scope: "Scope", send: "Send", message_id: int) -> None:
    assert scope["type"] == "http"
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [[b"content-type", b"text/html; charset=utf-8"]],
        }
    )
    message = error_messages.get(message_id) or "CSRF validation failed"
    await send({"type": "http.response.body", "body": message.encode("utf-8")})


def asgi_csrf(
    app,
    cookie_name: str = DEFAULT_COOKIE_NAME,
    http_header: str = DEFAULT_HTTP_HEADER,
    signing_secret: Optional[str] = None,
    signing_namespace: str = DEFAULT_SIGNING_NAMESPACE,
    always_protect: Optional[Container[str]] = None,
    always_set_cookie: bool = False,
    skip_if_scope: Optional[Callable[["Scope"], bool]] = None,
    cookie_path: str = DEFAULT_COOKIE_PATH,
    cookie_domain: Optional[str] = DEFAULT_COOKIE_DOMAIN,
    cookie_secure: bool = DEFAULT_COOKIE_SECURE,
    cookie_samesite: str = DEFAULT_COOKIE_SAMESITE,
    send_csrf_failed: Optional[Callable[["Scope", "Send", int], Awaitable[None]]] = None,
) -> "ASGIApp":
    return asgi_csrf_decorator(
        cookie_name,
        http_header,
        signing_secret=signing_secret,
        signing_namespace=signing_namespace,
        always_protect=always_protect,
        always_set_cookie=always_set_cookie,
        skip_if_scope=skip_if_scope,
        cookie_path=cookie_path,
        cookie_domain=cookie_domain,
        cookie_secure=cookie_secure,
        cookie_samesite=cookie_samesite,
        send_csrf_failed=send_csrf_failed,
    )(app)


def cookies_from_scope(scope: "Scope") -> Dict[str, str]:
    cookie = dict(scope.get("headers") or {}).get(b"cookie")
    if not cookie:
        return {}
    simple_cookie = SimpleCookie()
    simple_cookie.load(cookie.decode("utf8"))
    return {key: morsel.value for key, morsel in simple_cookie.items()}


allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def make_secret(length: int) -> str:
    return "".join(secrets.choice(allowed_chars) for i in range(length))
