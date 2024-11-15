from asgi_lifespan import LifespanManager
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from asgi_csrf import asgi_csrf, Errors
from itsdangerous.url_safe import URLSafeSerializer
import httpx
import json
import pytest

SECRET = "secret"


async def hello_world(request):
    if "csrftoken" in request.scope and "_no_token" not in request.query_params:
        request.scope["csrftoken"]()
    if request.method == "POST":
        data = await request.form()
        data = dict(data)
        if "csv" in data:
            data["csv"] = (await data["csv"].read()).decode("utf-8")
        return JSONResponse(data)
    headers = {}
    if "_vary" in request.query_params:
        headers["Vary"] = request.query_params["_vary"]
    return JSONResponse({"hello": "world"}, headers=headers)


async def hello_world_static(request):
    return JSONResponse({"hello": "world", "static": True})


hello_world_app = Starlette(
    routes=[
        Route("/", hello_world, methods=["GET", "POST"]),
        Route("/static", hello_world_static, methods=["GET"]),
        Route("/api/", hello_world_static, methods=["POST"]),
        Route("/api/foo", hello_world_static, methods=["POST"]),
    ]
)


@pytest.fixture
def app_csrf():
    return asgi_csrf(hello_world_app, signing_secret=SECRET)


async def custom_csrf_failed(scope, send, message_id):
    assert scope["type"] == "http"
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [[b"content-type", b"text/html; charset=utf-8"]],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": {
                Errors.FORM_URLENCODED_MISMATCH: "custom form-urlencoded error",
                Errors.MULTIPART_MISMATCH: "custom multipart error",
                Errors.FILE_BEFORE_TOKEN: "custom file before token error",
                Errors.UNKNOWN_CONTENT_TYPE: "custom unknown content type error",
            }
            .get(message_id, "")
            .encode("utf-8"),
        }
    )


@pytest.fixture
def app_csrf_custom_errors():
    return asgi_csrf(
        hello_world_app,
        signing_secret=SECRET,
        send_csrf_failed=custom_csrf_failed,
    )


@pytest.fixture
def csrftoken():
    return URLSafeSerializer(SECRET).dumps("token", "csrftoken")


@pytest.mark.asyncio
async def test_hello_world_app():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=hello_world_app)
    ) as client:
        response = await client.get("http://localhost/")
    assert b'{"hello":"world"}' == response.content


def test_signing_secret_if_none_provided(monkeypatch):
    app = asgi_csrf(hello_world_app)

    # Should be randomly generated
    def _get_secret_key(app):
        found = [
            cell.cell_contents
            for cell in app.__closure__
            if "URLSafeSerializer" in repr(cell)
        ]
        assert found
        return found[0].secret_key

    assert isinstance(_get_secret_key(app), bytes)
    # Should pick up `ASGI_CSRF_SECRET` if available
    monkeypatch.setenv("ASGI_CSRF_SECRET", "secret-from-environment")
    app2 = asgi_csrf(hello_world_app)
    assert _get_secret_key(app2) == b"secret-from-environment"


@pytest.mark.asyncio
async def test_asgi_csrf_sets_cookie(app_csrf):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_csrf)) as client:
        response = await client.get("http://localhost/")
    assert b'{"hello":"world"}' == response.content
    assert "csrftoken" in response.cookies
    assert response.headers["set-cookie"].endswith("; Path=/; SameSite=Lax")
    assert "Cookie" == response.headers["vary"]


@pytest.mark.asyncio
async def test_asgi_csrf_modifies_existing_vary_header(app_csrf):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_csrf)) as client:
        response = await client.get("http://localhost/?_vary=User-Agent")
    assert b'{"hello":"world"}' == response.content
    assert "csrftoken" in response.cookies
    assert response.headers["set-cookie"].endswith("; Path=/; SameSite=Lax")
    assert "User-Agent, Cookie" == response.headers["vary"]


@pytest.mark.asyncio
async def test_asgi_csrf_sets_no_cookie_or_vary_if_page_has_no_form(app_csrf):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_csrf)) as client:
        response = await client.get("http://localhost/static")
    assert b'{"hello":"world","static":true}' == response.content
    assert "csrftoken" not in response.cookies
    assert "vary" not in response.headers


@pytest.mark.asyncio
async def test_vary_header_only_if_page_contains_csrftoken(app_csrf, csrftoken):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_csrf), cookies={"csrftoken": csrftoken}
    ) as client:
        assert "vary" in (await client.get("http://localhost/")).headers
        assert "vary" not in (await client.get("http://localhost/?_no_token=1")).headers


@pytest.mark.asyncio
async def test_headers_passed_through_correctly(app_csrf):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_csrf)) as client:
        response = await client.get("http://localhost/static")
        assert "application/json" == response.headers["content-type"]


@pytest.mark.asyncio
async def test_asgi_csrf_does_not_set_cookie_if_one_sent(app_csrf, csrftoken):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_csrf), cookies={"csrftoken": csrftoken}
    ) as client:
        response = await client.get("http://localhost/")
    assert b'{"hello":"world"}' == response.content
    assert "csrftoken" not in response.cookies


@pytest.mark.asyncio
async def test_prevents_post_if_cookie_not_sent_in_post(app_csrf, csrftoken):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_csrf), cookies={"csrftoken": csrftoken}
    ) as client:
        response = await client.post("http://localhost/")
    assert 403 == response.status_code


@pytest.mark.asyncio
@pytest.mark.parametrize("custom_errors", (False, True))
async def test_prevents_post_if_cookie_not_sent_in_post(
    custom_errors, app_csrf, app_csrf_custom_errors, csrftoken
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app_csrf_custom_errors if custom_errors else app_csrf
        ),
        cookies={"csrftoken": csrftoken},
    ) as client:
        response = await client.post(
            "http://localhost/",
            data={"csrftoken": csrftoken[-1]},
        )
    assert 403 == response.status_code
    assert (
        response.text == "custom form-urlencoded error"
        if custom_errors
        else "form-urlencoded POST field did not match cookie"
    )


@pytest.mark.asyncio
async def test_allows_post_if_cookie_duplicated_in_header(app_csrf, csrftoken):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_csrf), cookies={"csrftoken": csrftoken}
    ) as client:
        response = await client.post(
            "http://localhost/",
            headers={"x-csrftoken": csrftoken},
        )
    assert 200 == response.status_code


@pytest.mark.asyncio
async def test_allows_post_if_cookie_duplicated_in_post_data(csrftoken):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=asgi_csrf(hello_world_app, signing_secret=SECRET)
        ),
        cookies={"csrftoken": csrftoken},
    ) as client:
        response = await client.post(
            "http://localhost/",
            data={"csrftoken": csrftoken, "hello": "world"},
        )
    assert 200 == response.status_code
    assert {"csrftoken": csrftoken, "hello": "world"} == json.loads(response.content)


@pytest.mark.asyncio
async def test_multipart(csrftoken):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=asgi_csrf(hello_world_app, signing_secret=SECRET)
        ),
        cookies={"csrftoken": csrftoken},
    ) as client:
        response = await client.post(
            "http://localhost/",
            data={"csrftoken": csrftoken},
            files={"csv": ("data.csv", "blah,foo\n1,2", "text/csv")},
        )
        assert response.status_code == 200
        assert response.json() == {"csrftoken": csrftoken, "csv": "blah,foo\n1,2"}


@pytest.mark.asyncio
@pytest.mark.parametrize("custom_errors", (False, True))
async def test_multipart_failure_wrong_token(csrftoken, custom_errors):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=asgi_csrf(
                hello_world_app,
                signing_secret=SECRET,
                send_csrf_failed=custom_csrf_failed if custom_errors else None,
            )
        ),
        cookies={"csrftoken": csrftoken[:-1]},
    ) as client:
        response = await client.post(
            "http://localhost/",
            data={"csrftoken": csrftoken},
            files={"csv": ("data.csv", "blah,foo\n1,2", "text/csv")},
        )
        assert response.status_code == 403
        assert (
            response.text == "custom multipart error"
            if custom_errors
            else "multipart/form-data POST field did not match cookie"
        )


class TrickEmptyDictionary(dict):
    # https://github.com/simonw/asgi-csrf/pull/14#issuecomment-674424080
    def __bool__(self):
        return True


@pytest.mark.asyncio
@pytest.mark.parametrize("custom_errors", (False, True))
async def test_multipart_failure_missing_token(csrftoken, custom_errors):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=asgi_csrf(
                hello_world_app,
                signing_secret=SECRET,
                send_csrf_failed=custom_csrf_failed if custom_errors else None,
            )
        ),
        cookies={"csrftoken": csrftoken},
    ) as client:
        response = await client.post(
            "http://localhost/",
            data={"foo": "bar"},
            files=TrickEmptyDictionary(),
        )
        assert response.status_code == 403
        assert response.text == (
            "custom multipart error"
            if custom_errors
            else "multipart/form-data POST field did not match cookie"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("custom_errors", (False, True))
async def test_multipart_failure_file_comes_before_token(csrftoken, custom_errors):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=asgi_csrf(
                hello_world_app,
                signing_secret=SECRET,
                send_csrf_failed=custom_csrf_failed if custom_errors else None,
            )
        )
    ) as client:
        request = httpx.Request(
            url="http://localhost/",
            method="POST",
            content=(
                b"--boo\r\n"
                b'Content-Disposition: form-data; name="csv"; filename="data.csv"'
                b"\r\nContent-Type: text/csv\r\n\r\n"
                b"blah,foo\n1,2"
                b"\r\n"
                b"--boo\r\n"
                b'Content-Disposition: form-data; name="csrftoken"\r\n\r\n'
                + csrftoken.encode("utf-8")
                + b"\r\n"
                b"--boo--\r\n"
            ),
            headers={"content-type": "multipart/form-data; boundary=boo"},
            cookies={"csrftoken": csrftoken},
        )
        response = await client.send(request)
        assert response.status_code == 403
        assert (
            response.text == "custom file before token error"
            if custom_errors
            else "File encountered before csrftoken - make sure csrftoken is first in the HTML"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization,expected_status", [("Bearer xxx", 200), ("Basic xxx", 403)]
)
async def test_post_with_authorization(authorization, expected_status):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=asgi_csrf(hello_world_app, signing_secret=SECRET)
        ),
        cookies={"foo": "bar"},
    ) as client:
        response = await client.post(
            "http://localhost/",
            headers={"Authorization": authorization},
        )
        assert expected_status == response.status_code


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cookies,path,expected_status",
    [
        ({}, "/", 200),
        ({"foo": "bar"}, "/", 403),
        ({}, "/login", 403),
        ({"foo": "bar"}, "/login", 403),
    ],
)
async def test_no_cookies_skips_check_unless_path_required(
    cookies, path, expected_status
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=asgi_csrf(
                hello_world_app, signing_secret=SECRET, always_protect={"/login"}
            )
        ),
        cookies=cookies,
    ) as client:
        response = await client.post("http://localhost{}".format(path))
        assert expected_status == response.status_code


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cookies,path,expected_status",
    [
        ({}, "/", 200),
        ({"foo": "bar"}, "/", 403),
        ({}, "/api/", 200),
        ({"foo": "bar"}, "/api/", 200),
        ({}, "/api/foo", 200),
        ({"foo": "bar"}, "/api/foo", 200),
    ],
)
async def test_skip_if_scope(cookies, path, expected_status):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=asgi_csrf(
                hello_world_app,
                signing_secret=SECRET,
                skip_if_scope=lambda scope: scope["path"].startswith("/api/"),
            )
        ),
        cookies=cookies,
    ) as client:
        response = await client.post("http://localhost{}".format(path))
        assert expected_status == response.status_code


@pytest.mark.asyncio
@pytest.mark.parametrize("always_set_cookie", [True, False])
async def test_always_set_cookie(always_set_cookie):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=asgi_csrf(
                hello_world_app,
                signing_secret=SECRET,
                always_set_cookie=always_set_cookie,
            )
        )
    ) as client:
        response = await client.get("http://localhost/static")
        assert 200 == response.status_code
        if always_set_cookie:
            assert "csrftoken" in response.cookies
        else:
            assert "csrftoken" not in response.cookies


@pytest.mark.asyncio
@pytest.mark.parametrize("send_csrftoken_cookie", [True, False])
async def test_always_set_cookie_unless_cookie_is_set(send_csrftoken_cookie, csrftoken):
    cookies = {}
    if send_csrftoken_cookie:
        cookies["csrftoken"] = csrftoken
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=asgi_csrf(
                hello_world_app, signing_secret=SECRET, always_set_cookie=True
            )
        ),
        cookies=cookies,
    ) as client:
        response = await client.get("http://localhost/static")
        assert 200 == response.status_code
        if send_csrftoken_cookie:
            assert "csrftoken" not in response.cookies
        else:
            assert "csrftoken" in response.cookies


@pytest.mark.asyncio
async def test_asgi_lifespan():
    app = asgi_csrf(hello_world_app, signing_secret=SECRET)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            cookies={"foo": "bar"},
        ) as client:
            response = await client.post(
                "http://localhost/",
                headers={"Authorization": "Bearer xxx"},
            )
            assert 200 == response.status_code


# Tests for different cookie options


@pytest.mark.asyncio
@pytest.mark.parametrize("cookie_name", ["csrftoken", "custom_csrf"])
async def test_cookie_name(cookie_name):
    wrapped_app = asgi_csrf(
        hello_world_app, signing_secret="secret", cookie_name=cookie_name
    )
    transport = httpx.ASGITransport(app=wrapped_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        response = await client.get("http://testserver/")
    assert cookie_name in response.cookies


@pytest.mark.asyncio
@pytest.mark.parametrize("cookie_path", ["/", "/custom"])
async def test_cookie_path(cookie_path):
    wrapped_app = asgi_csrf(
        hello_world_app, signing_secret="secret", cookie_path=cookie_path
    )
    transport = httpx.ASGITransport(app=wrapped_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        response = await client.get("http://testserver/")
    assert f"Path={cookie_path}" in response.headers["set-cookie"]


@pytest.mark.asyncio
@pytest.mark.parametrize("cookie_domain", [None, "example.com"])
async def test_cookie_domain(cookie_domain):
    wrapped_app = asgi_csrf(
        hello_world_app, signing_secret="secret", cookie_domain=cookie_domain
    )
    transport = httpx.ASGITransport(app=wrapped_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        response = await client.get("http://testserver/")
    if cookie_domain:
        assert f"Domain={cookie_domain}" in response.headers["set-cookie"]
    else:
        assert "Domain" not in response.headers["set-cookie"]


@pytest.mark.asyncio
@pytest.mark.parametrize("cookie_secure", [True, False])
async def test_cookie_secure(cookie_secure):
    wrapped_app = asgi_csrf(
        hello_world_app, signing_secret="secret", cookie_secure=cookie_secure
    )
    transport = httpx.ASGITransport(app=wrapped_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        response = await client.get("http://testserver/")
    if cookie_secure:
        assert "Secure" in response.headers["set-cookie"]
    else:
        assert "Secure" not in response.headers["set-cookie"]


@pytest.mark.asyncio
@pytest.mark.parametrize("cookie_samesite", ["Strict", "Lax", "None"])
async def test_cookie_samesite(cookie_samesite):
    wrapped_app = asgi_csrf(
        hello_world_app, signing_secret="secret", cookie_samesite=cookie_samesite
    )
    transport = httpx.ASGITransport(app=wrapped_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        response = await client.get("http://testserver/")
    assert f"SameSite={cookie_samesite}" in response.headers["set-cookie"]


@pytest.mark.asyncio
async def test_default_cookie_options():
    wrapped_app = asgi_csrf(hello_world_app, signing_secret="secret")
    transport = httpx.ASGITransport(app=wrapped_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        response = await client.get("http://testserver/")
    set_cookie = response.headers["set-cookie"]
    assert "csrftoken" in set_cookie
    assert "Path=/" in set_cookie
    assert "Domain" not in set_cookie
    assert "Secure" not in set_cookie
    assert "SameSite=Lax" in set_cookie
