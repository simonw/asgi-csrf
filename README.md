# asgi-csrf

[![PyPI](https://img.shields.io/pypi/v/asgi-csrf.svg)](https://pypi.org/project/asgi-csrf/)
[![CircleCI](https://circleci.com/gh/simonw/asgi-csrf.svg?style=svg)](https://circleci.com/gh/simonw/asgi-csrf)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/asgi-csrf/blob/master/LICENSE)

ASGI middleware for protecting against CSRF attacks

**This is a preview release - do not assume that this is robust and secure just yet.**

## Installation

    pip install asgi-csrf

## Background

See the [OWASP guide to Cross Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf) and their [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet).

This middleware implements the Double Submit Cookie pattern, where a cookie is set that is then compared to a `csrftoken` hidden form field or a `x-csrftoken` HTTP header.

## Limitations

* Brand new. Not extensively tested. Do not trust this yet.
* Currently only works for `application/x-www-form-urlencoded` forms, not `multipart/form-data` forms (with file uploads)
