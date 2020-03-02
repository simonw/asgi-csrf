from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from asgi_csrf import asgi_csrf
import httpx
import json
import pytest

CSRF_TOKEN = "9izX9q37XP9knNNQ"


async def hello_world(request):
    if request.method == "POST":
        data = await request.form()
        return JSONResponse(dict(await request.form()))
    return JSONResponse({"hello": "world"})


hello_world_app = Starlette(routes=[Route("/", hello_world, methods=["GET", "POST"]),])


@pytest.mark.asyncio
async def test_hello_world_app():
    async with httpx.AsyncClient(app=hello_world_app) as client:
        response = await client.get("http://localhost/")
    assert b'{"hello":"world"}' == response.content


@pytest.mark.asyncio
async def test_asgi_csrf_sets_cookie():
    async with httpx.AsyncClient(app=asgi_csrf(hello_world_app)) as client:
        response = await client.get("http://localhost/")
    assert b'{"hello":"world"}' == response.content
    assert "csrftoken" in response.cookies


@pytest.mark.asyncio
async def test_asgi_csrf_does_not_set_cookie_if_one_sent():
    async with httpx.AsyncClient(app=asgi_csrf(hello_world_app)) as client:
        response = await client.get(
            "http://localhost/", cookies={"csrftoken": CSRF_TOKEN}
        )
    assert b'{"hello":"world"}' == response.content
    assert "csrftoken" not in response.cookies


@pytest.mark.asyncio
async def test_prevents_post_if_no_cookie():
    async with httpx.AsyncClient(app=asgi_csrf(hello_world_app)) as client:
        response = await client.post("http://localhost/")
    assert 403 == response.status_code


@pytest.mark.asyncio
async def test_prevents_post_if_cookie_not_sent_in_post():
    async with httpx.AsyncClient(app=asgi_csrf(hello_world_app)) as client:
        response = await client.post(
            "http://localhost/", cookies={"csrftoken": CSRF_TOKEN}
        )
    assert 403 == response.status_code


@pytest.mark.asyncio
async def test_allows_post_if_cookie_duplicated_in_header():
    async with httpx.AsyncClient(app=asgi_csrf(hello_world_app)) as client:
        response = await client.post(
            "http://localhost/",
            headers={"X-CSRFToken": CSRF_TOKEN},
            cookies={"csrftoken": CSRF_TOKEN},
        )
    assert 200 == response.status_code


@pytest.mark.asyncio
async def test_allows_post_if_cookie_duplicated_in_post_data():
    async with httpx.AsyncClient(app=asgi_csrf(hello_world_app)) as client:
        response = await client.post(
            "http://localhost/",
            data={"csrftoken": CSRF_TOKEN, "hello": "world"},
            cookies={"csrftoken": CSRF_TOKEN},
        )
    assert 200 == response.status_code
    assert {"csrftoken": CSRF_TOKEN, "hello": "world"} == json.loads(response.content)


@pytest.mark.asyncio
async def test_multipart_not_supported():
    async with httpx.AsyncClient(app=asgi_csrf(hello_world_app)) as client:
        with pytest.raises(AssertionError):
            response = await client.post(
                "http://localhost/",
                data={"csrftoken": CSRF_TOKEN},
                files={"csv": ("data.csv", "blah,foo\n1,2", "text/csv")},
                cookies={"csrftoken": CSRF_TOKEN},
            )
