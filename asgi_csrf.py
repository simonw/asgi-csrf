from http.cookies import SimpleCookie
import fnmatch
from functools import wraps
from urllib.parse import parse_qsl
import secrets

DEFAULT_COOKIE_NAME = "csrftoken"
DEFAULT_FORM_INPUT = "csrftoken"
DEFAULT_HTTP_HEADER = "x-csrftoken"
SCOPE_KEY = "csrftoken"


def asgi_csrf_decorator(
    cookie_name=DEFAULT_COOKIE_NAME,
    http_header=DEFAULT_HTTP_HEADER,
    form_input=DEFAULT_FORM_INPUT,
):
    def _asgi_csrf_decorator(app):
        @wraps(app)
        async def app_wrapped_with_csrf(scope, receive, send):
            cookies = cookies_from_scope(scope)
            csrftoken = None
            should_set_cookie = False
            if cookie_name in cookies:
                csrftoken = cookies[cookie_name]
            else:
                # We are going to set that cookie
                should_set_cookie = True
                csrftoken = make_secret(16)
            scope = {**scope, **{SCOPE_KEY: csrftoken}}

            async def wrapped_send(event):
                if event["type"] == "http.response.start":
                    if should_set_cookie:
                        original_headers = event.get("headers") or []
                        set_cookie_headers = [
                            (
                                b"set-cookie",
                                "{}={}".format(cookie_name, csrftoken).encode("utf-8"),
                            )
                        ]
                        event = {
                            "type": "http.response.start",
                            "status": event["status"],
                            "headers": original_headers + set_cookie_headers,
                        }
                await send(event)

            # Apply to anything that isn't GET, HEAD, OPTIONS, TRACE (like Django does)
            if scope["method"] in {"GET", "HEAD", "OPTIONS", "TRACE"}:
                await app(scope, receive, wrapped_send)
            else:
                # Check for CSRF token in various places
                headers = dict(scope.get("headers" or []))
                if (
                    headers.get(http_header.encode("latin-1"), b"").decode("latin-1")
                    == csrftoken
                ):
                    # x-csrftoken header matches
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
                            scope, wrapped_send, "POST field did not match cookie"
                        )
                        return
                elif content_type == b"multipart/form-data":
                    # Consume non-file items until we see a csrftoken
                    # If we see a file item first, it's an error
                    assert False, "multipart/form-data is not yet supported"
                else:
                    await send_csrf_failed(
                        scope, wrapped_send, message="Unknown content-type"
                    )
                    return

        return app_wrapped_with_csrf

    return _asgi_csrf_decorator


async def _parse_form_urlencoded(receive):
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

    async def replay_receive():
        return messages.pop(0)

    return dict(parse_qsl(body.decode("utf-8"))), replay_receive


async def send_csrf_failed(scope, send, message="CSRF check failed"):
    assert scope["type"] == "http"
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [[b"content-type", b"text/html; charset=utf-8"]],
        }
    )
    await send({"type": "http.response.body", "body": message.encode("utf-8")})


def asgi_csrf(app, cookie_name=DEFAULT_COOKIE_NAME, http_header=DEFAULT_HTTP_HEADER):
    return asgi_csrf_decorator(cookie_name, http_header)(app)


def cookies_from_scope(scope):
    cookie = dict(scope.get("headers") or {}).get(b"cookie")
    if not cookie:
        return {}
    simple_cookie = SimpleCookie()
    simple_cookie.load(cookie.decode("utf8"))
    return {key: morsel.value for key, morsel in simple_cookie.items()}


allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def make_secret(length):
    return "".join(secrets.choice(allowed_chars) for i in range(length))
