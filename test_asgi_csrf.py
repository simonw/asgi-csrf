from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from asgi_csrf import asgi_csrf
from itsdangerous.url_safe import URLSafeSerializer
import httpx
import json
import pytest

SECRET = "secret"


async def hello_world(request):
    if request.method == "POST":
        data = await request.form()
        return JSONResponse(dict(await request.form()))
    return JSONResponse({"hello": "world"})


hello_world_app = Starlette(routes=[Route("/", hello_world, methods=["GET", "POST"]),])


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


@pytest.mark.asyncio
async def test_asgi_csrf_sets_cookie(app_csrf):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.get("http://localhost/")
    assert b'{"hello":"world"}' == response.content
    assert "csrftoken" in response.cookies
    assert response.headers["set-cookie"].endswith("; Path=/")


@pytest.mark.asyncio
async def test_asgi_csrf_does_not_set_cookie_if_one_sent(app_csrf, csrftoken):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.get(
            "http://localhost/", cookies={"csrftoken": csrftoken}
        )
    assert b'{"hello":"world"}' == response.content
    assert "csrftoken" not in response.cookies


@pytest.mark.asyncio
async def test_prevents_post_if_no_cookie(app_csrf):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.post("http://localhost/")
    assert 403 == response.status_code


@pytest.mark.asyncio
async def test_prevents_post_if_cookie_not_sent_in_post(app_csrf, csrftoken):
    async with httpx.AsyncClient(app=app_csrf) as client:
        response = await client.post(
            "http://localhost/", cookies={"csrftoken": csrftoken}
        )
    assert 403 == response.status_code


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
async def test_multipart_not_supported(csrftoken):
    async with httpx.AsyncClient(app=asgi_csrf(hello_world_app)) as client:
        with pytest.raises(AssertionError):
            response = await client.post(
                "http://localhost/",
                data={"csrftoken": csrftoken},
                files={"csv": ("data.csv", "blah,foo\n1,2", "text/csv")},
                cookies={"csrftoken": csrftoken},
            )
