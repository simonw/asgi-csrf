from asgi_csrf import asgi_csrf
import httpx
import pytest

CSRF_TOKEN = "9izX9q37XP9knNNQ"


async def hello_world_app(scope, receive, send):
    assert scope["type"] == "http"
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [[b"content-type", b"application/json"]],
        }
    )
    await send({"type": "http.response.body", "body": b'{"hello": "world"}'})


@pytest.mark.asyncio
async def test_hello_world_app():
    async with httpx.AsyncClient(app=hello_world_app) as client:
        response = await client.get("http://localhost/")
    assert b'{"hello": "world"}' == response.content


@pytest.mark.asyncio
async def test_asgi_csrf_sets_cookie():
    async with httpx.AsyncClient(app=asgi_csrf(hello_world_app)) as client:
        response = await client.get("http://localhost/")
    assert b'{"hello": "world"}' == response.content
    assert "csrftoken" in response.cookies


@pytest.mark.asyncio
async def test_asgi_csrf_does_not_set_cookie_if_one_sent():
    async with httpx.AsyncClient(app=asgi_csrf(hello_world_app)) as client:
        response = await client.get(
            "http://localhost/", cookies={"csrftoken": CSRF_TOKEN}
        )
    assert b'{"hello": "world"}' == response.content
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
            data={"csrftoken": CSRF_TOKEN},
            cookies={"csrftoken": CSRF_TOKEN},
        )
    assert 200 == response.status_code


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
