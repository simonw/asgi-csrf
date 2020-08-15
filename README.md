# asgi-csrf

[![PyPI](https://img.shields.io/pypi/v/asgi-csrf.svg)](https://pypi.org/project/asgi-csrf/)
[![Changelog](https://img.shields.io/github/v/release/simonw/asgi-csrf?include_prereleases&label=changelog)](https://github.com/simonw/asgi-csrf/releases)
[![codecov](https://codecov.io/gh/simonw/asgi-csrf/branch/main/graph/badge.svg)](https://codecov.io/gh/simonw/asgi-csrf)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/asgi-csrf/blob/main/LICENSE)

ASGI middleware for protecting against CSRF attacks

## Installation

    pip install asgi-csrf

## Background

See the [OWASP guide to Cross Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf) and their [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

This middleware implements the [Double Submit Cookie pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie), where a cookie is set that is then compared to a `csrftoken` hidden form field or a `x-csrftoken` HTTP header.

## Usage

Decorate your ASGI application like this:

```python
from asgi_csrf import asgi_csrf
from .my_asgi_app import app


app = asgi_csrf(app, signing_secret="secret-goes-here")
```

The middleware will set a `csrftoken` cookie, if one is missing. The value of that token will be made available to your ASGI application through the `scope["csrftoken"]` function.

Your application code should include that value as a hidden form field in any POST forms:

```html
<form action="/login" method="POST">
    ...
    <input type="hidden" name="csrftoken" value="{{ request.scope.csrftoken() }}">
</form>
```

Note that `request.scope["csrftoken"]` is a function that returns a string. Calling that function also lets the middleware know that the cookie should be set by that page, if the user does not already have that cookie.

If the cookie needs to be set, the middleware will add a `Vary: Cookie` header to the response to ensure it is not incorrectly cached by any CDNs or intermediary proxies.

The middleware will return a 403 forbidden error for any POST requests that do not include the matching `csrftoken` - either in the POST data or in a `x-csrftoken` HTTP header (useful for JavaScript `fetch()` calls).

The `signing_secret` is used to sign the tokens, to protect against subdomain vulnerabilities.

If you do not pass in an explicit `signing_secret` parameter, the middleware will look for a `ASGI_CSRF_SECRET` environment variable.

If it cannot find that environment variable, it will generate a random secret which will persist for the lifetime of the server.

This means that if you do not configure a specific secret your user's `csrftoken` cookies will become invalid every time the server restarts! You should configure a secret.

## Other cases that skip CSRF protection

If the request includes an `Authorization: Bearer ...` header, commonly used by OAuth and JWT authentication, the request will not be required to include a CSRF token. This is because browsers cannot send those headers in a context that can be abused.

If the request has no cookies at all it will be allowed through, since CSRF protection is only necessary for requests from authenticated users.

If you have paths that should always be protected even without cookies - your login form for example (to avoid [login CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#login-csrf) attacks) you can protect those paths by passing them as the ``always_protect`` parameter:

```python
app = asgi_csrf(
    app,
    signing_secret="secret-goes-here",
    always_protect={"/login"}
)
```
