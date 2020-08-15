from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from asgi_csrf import asgi_csrf
from itsdangerous.url_safe import URLSafeSerializer
import httpx
import json
import os
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
    ]
)


@pytest.fixture
def app_csrf():
    return asgi_csrf(hello_world_app, signing_secret=SECRET)


@pytest.fixture
def csrftoken():
    return URLSafeSerializer(SECRET).dumps("token", "csrftoken")


@pytest.mark.asyncio
async def test_hello_world_app():
    async with httpx.AsyncClient(app=hello_world_app) as client:
        response = await client.get("http://localhost/")
    assert b'{"hello":"world"}' == response.content


def test_signing_secret_if_none_provided(monkeypatch):
    app = asgi_csrf(hello_world_app)
    # Should be randomly generated
    assert isinstance(app.__closure__[5].cell_contents.secret_key, bytes)
    # Should pick up `ASGI_CSRF_SECRET` if available
    monkeypatch.setenv("ASGI_CSRF_SECRET", "secret-from-environment")
    app2 = asgi_csrf(hello_world_app)
    assert app2.__closure__[5].cell_contents.secret_key == b"secret-from-environment"


@pytest.mark.asyncio
async def test_asgi_csrf_sets_cookie(app_csrf):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.get("http://localhost/")
    assert b'{"hello":"world"}' == response.content
    assert "csrftoken" in response.cookies
    assert response.headers["set-cookie"].endswith("; Path=/")
    assert "Cookie" == response.headers["vary"]


@pytest.mark.asyncio
async def test_asgi_csrf_modifies_existing_vary_header(app_csrf):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.get("http://localhost/?_vary=User-Agent")
    assert b'{"hello":"world"}' == response.content
    assert "csrftoken" in response.cookies
    assert response.headers["set-cookie"].endswith("; Path=/")
    assert "User-Agent, Cookie" == response.headers["vary"]


@pytest.mark.asyncio
async def test_asgi_csrf_sets_no_cookie_or_vary_if_page_has_no_form(app_csrf):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.get("http://localhost/static")
    assert b'{"hello":"world","static":true}' == response.content
    assert "csrftoken" not in response.cookies
    assert "vary" not in response.headers


@pytest.mark.asyncio
async def test_vary_header_only_if_page_contains_csrftoken(app_csrf, csrftoken):
    async with httpx.AsyncClient(app=app_csrf) as client:
        assert (
            "vary"
            in (
                await client.get("http://localhost/", cookies={"csrftoken": csrftoken})
            ).headers
        )
        assert (
            "vary"
            not in (
                await client.get(
                    "http://localhost/?_no_token=1", cookies={"csrftoken": csrftoken}
                )
            ).headers
        )


@pytest.mark.asyncio
async def test_headers_passed_through_correctly(app_csrf):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.get("http://localhost/static")
        assert "application/json" == response.headers["content-type"]


@pytest.mark.asyncio
async def test_asgi_csrf_does_not_set_cookie_if_one_sent(app_csrf, csrftoken):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.get(
            "http://localhost/", cookies={"csrftoken": csrftoken}
        )
    assert b'{"hello":"world"}' == response.content
    assert "csrftoken" not in response.cookies


@pytest.mark.asyncio
async def test_prevents_post_if_cookie_not_sent_in_post(app_csrf, csrftoken):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.post(
            "http://localhost/", cookies={"csrftoken": csrftoken}
        )
    assert 403 == response.status_code


@pytest.mark.asyncio
async def test_prevents_post_if_cookie_not_sent_in_post(app_csrf, csrftoken):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.post(
            "http://localhost/", cookies={"csrftoken": csrftoken},
            data={"csrftoken": csrftoken[-1]},
        )
    assert 403 == response.status_code
    assert response.text == 'form-urlencoded POST field did not match cookie'


@pytest.mark.asyncio
async def test_allows_post_if_cookie_duplicated_in_header(app_csrf, csrftoken):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.post(
            "http://localhost/",
            headers={"x-csrftoken": csrftoken},
            cookies={"csrftoken": csrftoken},
        )
    assert 200 == response.status_code


@pytest.mark.asyncio
async def test_allows_post_if_cookie_duplicated_in_post_data(csrftoken):
    async with httpx.AsyncClient(
        app=asgi_csrf(hello_world_app, signing_secret=SECRET)
    ) as client:
        response = await client.post(
            "http://localhost/",
            data={"csrftoken": csrftoken, "hello": "world"},
            cookies={"csrftoken": csrftoken},
        )
    assert 200 == response.status_code
    assert {"csrftoken": csrftoken, "hello": "world"} == json.loads(response.content)


@pytest.mark.asyncio
async def test_multipart(csrftoken):
    async with httpx.AsyncClient(
        app=asgi_csrf(hello_world_app, signing_secret=SECRET)
    ) as client:
        response = await client.post(
            "http://localhost/",
            data={"csrftoken": csrftoken},
            files={"csv": ("data.csv", "blah,foo\n1,2", "text/csv")},
            cookies={"csrftoken": csrftoken},
        )
        assert response.status_code == 200
        assert response.json() == {"csrftoken": csrftoken, "csv": "blah,foo\n1,2"}


@pytest.mark.asyncio
async def test_multipart_failure(csrftoken):
    async with httpx.AsyncClient(
        app=asgi_csrf(hello_world_app, signing_secret=SECRET)
    ) as client:
        response = await client.post(
            "http://localhost/",
            data={"csrftoken": csrftoken},
            files={"csv": ("data.csv", "blah,foo\n1,2", "text/csv")},
            cookies={"csrftoken": csrftoken[:-1]},
        )
        assert response.status_code == 403
        assert response.text == "multipart/form-data POST field did not match cookie"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization,expected_status", [("Bearer xxx", 200), ("Basic xxx", 403)]
)
async def test_post_with_authorization(authorization, expected_status):
    async with httpx.AsyncClient(
        app=asgi_csrf(hello_world_app, signing_secret=SECRET)
    ) as client:
        response = await client.post(
            "http://localhost/",
            headers={"Authorization": authorization},
            cookies={"foo": "bar"},
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
        app=asgi_csrf(hello_world_app, signing_secret=SECRET, always_protect={"/login"})
    ) as client:
        response = await client.post("http://localhost{}".format(path), cookies=cookies)
        assert expected_status == response.status_code
