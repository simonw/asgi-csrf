from setuptools import setup
import os

VERSION = "0.8"


def get_long_description():
    with open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md"),
        encoding="utf8",
    ) as fp:
        return fp.read()


setup(
    name="asgi-csrf",
    description="ASGI middleware for protecting against CSRF attacks",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Simon Willison",
    url="https://github.com/simonw/asgi-csrf",
    license="Apache License, Version 2.0",
    version=VERSION,
    py_modules=["asgi_csrf"],
    install_requires=["itsdangerous", "python-multipart"],
    extras_require={
        "test": [
            "pytest",
            "pytest-asyncio",
            "httpx>=0.16",
            "starlette",
            "pytest-cov",
            "asgi-lifespan",
        ]
    },
)
