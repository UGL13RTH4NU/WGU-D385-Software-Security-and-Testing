# API Authentication in Flask — Walk-through/ Outline

*A tutorial-style reference for D385 Task 2 Section B, Vulnerability \#1 (Missing API Authentication / CWE-306). Concepts, patterns, and the "why" — designed to prepare you before you write your solution.*


## 1. Why do API endpoints need authentication?

Your Flask app currently has this in `require\_api\_key()`:

```
def require\_api\_key():  
    \# INSECURE: Currently returns None (no authentication)  
    return None
```

And endpoints like `/api/v1/rentals` have this commented out:

```
\# user = require\_api\_key()  
\# if not user:  
\#     return jsonify(\{"status": "error", "message": "Authentication required"\}), 401
```

That means **anyone on the network** can hit `curl http://your-server/api/v1/rentals` and get back every rental record — including SSNs — with no proof of who they are. This is CWE-306: **Missing Authentication for Critical Function.**

The web browser is not a security boundary. HTML forms, login pages, and "you must be logged in" banners are UI conveniences, not enforcement. Anyone can bypass them with `curl`, Postman, browser dev tools, or a homemade Python script. The **server** has to decide, on every single request, whether the caller is allowed to be there.

That decision is what authentication provides: "**Who are you, and can you prove it?**"


## 2. The core concepts (glossary)

| Term | What it means | Why it matters |
| - | - | - |
| **Authentication (AuthN)** | Verifying *who* the caller is. | Answers "are you who you say you are?" |
| **Authorization (AuthZ)** | Deciding *what* the caller can do. | Comes after AuthN. Covered in the next cheat sheet. |
| **API key** | A long, unguessable string that identifies a caller. Like a very fancy password. | Simple to implement, common for machine-to-machine APIs. |
| **HTTP header** | Key-value metadata sent with every request. | Where you put the API key — not in the URL. |
| **`Authorization` header** | The standard HTTP header for credentials. Format: `Authorization: \<scheme\> \<credentials\>` | Standardized by RFC 7235. Every API and library expects it. |
| **Bearer scheme** | The most common credential scheme: `Authorization: Bearer \<token\>` | Says "whoever holds this token is granted access." |
| **401 Unauthorized** | HTTP status code meaning "you didn't authenticate, or your credentials are bad." | Standard response when AuthN fails. Confusingly named — really means "unauthenticated." |
| **403 Forbidden** | HTTP status code meaning "you authenticated, but you're not allowed to do this." | AuthZ failure. Different from 401. |
| **Stateless** | The server doesn't remember prior requests. Each request must carry its own proof of identity. | Why APIs typically use tokens/keys instead of session cookies. |
| **CWE-598** | The weakness of putting sensitive data in URL query strings (`?api\_key=...`). | Why credentials go in headers, not URLs. See §7. |



## 3. The pattern you'll build — a conceptual walkthrough

Here's the general shape of an API-key authentication function. **This isn't your Task 2 solution** — it's a teaching skeleton showing the pieces you'll assemble.

```
from flask import request  
  
def check\_bearer\_token():  
    """General shape — not your assignment answer."""  
  
    \# 1. Read the Authorization header from the incoming request.  
    auth\_header = request.headers.get('Authorization')  
  
    \# 2. If the header is missing entirely, no point continuing.  
    if not auth\_header:  
        return None  
  
    \# 3. Split the header into scheme and credential parts.  
    \#    Expected format: "Bearer \<token\>"  
    parts = auth\_header.split()  
  
    \# 4. Verify the format is what we expect.  
    if len(parts) != 2 or parts\[0\] != 'Bearer':  
        return None  
  
    token = parts\[1\]  
  
    \# 5. Look up the token in your data store.  
    \#    Iterate the users, or use a token→user index.  
    for username, data in USERS\_DB.items():  
        if data.get('api\_key') == token:  
            return username   \# Found — return the identifier of the authenticated user.  
  
    \# 6. No match — token was well-formed but invalid.  
    return None
```

**What each step is really doing:**

- **`request.headers.get('Authorization')`** — Flask's `request` object exposes headers as a case-insensitive dictionary-like object. `.get()` returns `None` if the header isn't there, which is safer than `request.headers\['Authorization'\]` (that would raise `KeyError`).

- **`auth\_header.split()`** — `str.split()` without arguments splits on any whitespace and drops empty strings. For `"Bearer abc123"` you get `\["Bearer", "abc123"\]`. For malformed input like `"Bearer"` alone or `"BearerToken"`, the length check catches it.

- **The length + scheme check** — Defensive parsing. You want to reject anything that doesn't match the expected shape *before* trying to look up the token.

- **The lookup loop** — `USERS\_DB` is a nested dict of the form `\{username: \{"api\_key": "...", "role": "..."\}\}`. You need to walk it, comparing each stored `api\_key` to the presented token.

- **Return the identifier, not `True`** — The whole point of returning the username is so the caller (a route handler) knows *who* just authenticated. That's what enables the *authorization* step next.

### How the route will use it

The other half of the picture is how endpoints call your function:

```
@app.route('/api/v1/rentals', methods=\['GET'\])  
def get\_rentals():  
    user = require\_api\_key()  
    if not user:  
        return jsonify(\{"status": "error", "message": "Authentication required"\}), 401  
  
    \# Only reached if authenticated:  
    return jsonify(\{"status": "success", "data": \[...\]\})
```

The route asks "who is this?" then acts on the answer. `None` means "reject with 401." A username means "proceed."


## 4. Mandatory vs discretionary

### 🔴 Mandatory (violate these and it's broken)

| Rule | Why |
| - | - |
| Credentials go in the `Authorization` header, not the URL | URLs land in server logs, browser history, proxy caches, referrer headers. Headers don't (usually). This is what CWE-598 is about. |
| Return `401` when authentication fails | It's the standard HTTP status for "you didn't authenticate." Non-standard responses break clients. |
| The auth check runs on *every* protected endpoint | Missing it on even one endpoint defeats the whole system. |
| Compare the whole token, not a prefix | Prefix matching lets an attacker guess one character at a time. |
| Never leak *why* auth failed in the client response | "Wrong token" vs "user doesn't exist" tells an attacker which usernames are real. Just say "Authentication required." |


### 🟡 Discretionary (your call, all defensible)

| Choice | Reasonable options | Notes |
| - | - | - |
| Which credential scheme | `Bearer`, custom (`X-API-Key: ...`), Basic | `Bearer` is the standard for tokens. |
| Function return type | Username string / `None`, or user dict / `None`, or raise exception | Any is fine as long as callers handle it consistently. |
| Lookup strategy | Linear loop, dictionary index by key | For 4 users, a loop is fine. Real apps build a reverse index. |
| Error message wording | "Authentication required", "Missing or invalid credentials", etc. | Just don't be too specific (see mandatory column). |
| Whether to log failures | `logging.warning`, silent, or count them for rate limiting | Logging is usually good practice — helps detect brute force. |
| Where the credential store lives | In-memory dict, database, external identity provider | For this assignment, the in-memory `USERS\_DB`. |



## 5. Alternatives you could have used

### Option A — Manual API key check (what your assignment expects)

```
auth\_header = request.headers.get('Authorization')  
\# ...parse and validate against USERS\_DB...
```

- ✅ Standard library + Flask only — no extra dependencies.

- ✅ Full control over the logic.

- ✅ Easy to read and explain in a report.

- ❌ Verbose. Every protected endpoint needs the boilerplate.

### Option B — Flask decorator wrapping the check

```
from functools import wraps  
  
def require\_auth(f):  
    @wraps(f)  
    def wrapped(\*args, \*\*kwargs):  
        user = require\_api\_key()  
        if not user:  
            return jsonify(\{"error": "Authentication required"\}), 401  
        return f(\*args, \*\*kwargs)  
    return wrapped  
  
@app.route('/api/v1/rentals')  
@require\_auth  
def get\_rentals():  
    ...
```

- ✅ Cleaner endpoints — decorator does the boilerplate.

- ✅ Impossible to forget the check on a decorated route.

- ❌ Extra concept (decorators, `functools.wraps`) to understand.

### Option C — `Flask-HTTPAuth` library

```
\# pip install Flask-HTTPAuth  
from flask\_httpauth import HTTPTokenAuth  
  
auth = HTTPTokenAuth(scheme='Bearer')  
  
@auth.verify\_token  
def verify\_token(token):  
    for username, data in USERS\_DB.items():  
        if data\['api\_key'\] == token:  
            return username  
    return None  
  
@app.route('/api/v1/rentals')  
@auth.login\_required  
def get\_rentals():  
    return jsonify(...)
```

- ✅ Handles header parsing, 401 responses, and edge cases for you.

- ✅ Widely used, well-documented.

- ❌ Extra dependency.

- ❌ Hides the mechanics you're supposed to demonstrate for this assignment.

### Option D — JSON Web Tokens (JWT)

Instead of a random API key stored in a database, the token *itself* contains signed claims about the user:

```
\# pip install PyJWT  
import jwt  
  
payload = \{'user': 'alice', 'role': 'admin', 'exp': 1735689600\}  
token = jwt.encode(payload, secret\_key, algorithm='HS256')  
  
\# ...later, on the server:  
claims = jwt.decode(token, secret\_key, algorithms=\['HS256'\])  
username = claims\['user'\]
```

- ✅ Server doesn't have to store or look up tokens — the token is self-describing.

- ✅ Built-in expiration.

- ✅ Industry standard for modern REST APIs.

- ❌ More concepts (signing, claims, expiration, refresh tokens).

- ❌ Overkill for a 4-user assignment.

### Option E — OAuth 2.0 / OpenID Connect

The full industry pattern: a dedicated identity provider (Auth0, Okta, Google, Microsoft Entra) issues tokens, and your API just validates them.

- ✅ You don't manage credentials at all — the identity provider does.

- ✅ Supports SSO, MFA, social logins.

- ❌ Massive complexity for anything smaller than a real production app.

- ❌ Well beyond the scope of Task 2.

### Option F — Basic Auth

The original HTTP authentication scheme. Client sends `Authorization: Basic \<base64(user:pass)\>` with every request.

- ✅ Trivially simple.

- ✅ Every HTTP library supports it.

- ❌ Sends credentials on every request, so **only ever use over HTTPS**.

- ❌ No token expiration or rotation.

- ❌ Considered outdated for new APIs.

### Option G — Session cookies

Traditional web-app pattern: the server sets a `Set-Cookie` header after login, and the browser sends it back on every subsequent request.

- ✅ Automatic and invisible from the client's perspective.

- ✅ Well-suited to server-rendered web apps.

- ❌ Not a great fit for stateless REST APIs.

- ❌ Vulnerable to CSRF attacks if not defended properly.


## 6. Common mistakes to avoid

- ❌ **Putting the API key in the URL** (`/api/v1/rentals?api\_key=sk\_abc123`). This is CWE-598. URLs get logged everywhere; headers usually don't.

- ❌ **Comparing tokens with `==`.** Uses short-circuit comparison, which leaks timing information. Use `hmac.compare\_digest(a, b)` for anything you'd call a "secret." (For a 4-user assignment, `==` is a tolerable simplification, but know why the real-world answer is different.)

- ❌ **Returning `200 OK` with an error message body.** Clients rely on status codes. Unauthenticated requests must return `401`, not `200 \{"error": "..."\}`.

- ❌ **Rich error messages that leak state.** "User `alice` not found" tells an attacker which usernames don't exist. "Wrong password" tells them which do. Both go into "Authentication required."

- ❌ **Forgetting to check the scheme, not just the token.** `Authorization: NotBearer abc123` should be rejected even if `abc123` happens to be valid — the scheme is part of the contract.

- ❌ **Trusting `request.args` or form fields for credentials.** Both land in server access logs by default.

- ❌ **Sending credentials over plain HTTP.** Bearer tokens are *bearer* tokens — whoever intercepts one gets the access. HTTPS is mandatory in production. (Local dev over `http://127.0.0.1` is fine.)

- ❌ **Hardcoding credentials, again.** You just moved secrets out to env vars in Vulnerability \#1. Don't put them back in.

- ❌ **Skipping the auth check on "internal" routes.** An internal route that's routable from the public internet is a public route.

- ❌ **Applying the check inconsistently.** If `/api/v1/rentals` requires auth but `/api/v1/rentals-legacy` doesn't, attackers will find the second one.


## 7. Quick decision guide

| Situation | Use |
| - | - |
| Class assignment with fixed users in a dict | Manual API-key check with `request.headers.get('Authorization')` ✅ |
| Multiple protected endpoints, DRY code | Custom decorator wrapping the check |
| Small production app, want a library to handle edge cases | Flask-HTTPAuth |
| Modern REST API with users signing up, sessions, expiration | JWT |
| SaaS, enterprise, or user-facing app | OAuth 2.0 / OpenID Connect via a provider |
| Server-rendered traditional web app | Flask-Login with session cookies |
| Machine-to-machine, legacy compatibility over HTTPS | Basic Auth |



## 8. Beginner-friendly references

- **[Flask API Authentication for APIs: HTTP & Token Authentication — CodingNomads**](https://codingnomads.com/python-flask-authentication-http-token-authentication) — Clear walkthrough of the *why* behind API auth being different from web app auth. Explains statelessness well.

- **[API Authentication in Flask — Gitau Harrison**](https://www.gitauharrison.com/articles/apis-in-flask/authentication) — Progresses from Basic Auth → Token Auth → Bearer format. Shows how the Authorization header is parsed.

- **[Flask Bearer Token Authentication — Auth0**](https://developer.auth0.com/resources/code-samples/api/flask/basic-authorization) — Official reference for the Bearer scheme with production-quality patterns. Uses JWT but the header handling is universal.

- **[Flask-HTTPAuth Documentation**](https://flask-httpauth.readthedocs.io/) — The library docs are surprisingly readable and explain the concepts as they go, not just the API.

- **[MDN: HTTP Authentication**](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication) — The vendor-neutral reference for how HTTP auth works. Covers headers, status codes, schemes.

- **[RFC 6750 — Bearer Token Usage**](https://datatracker.ietf.org/doc/html/rfc6750) — The actual spec defining `Authorization: Bearer \<token\>`. Section 2.1 is 3 pages and worth reading once.

- **[CWE-306: Missing Authentication for Critical Function**](https://cwe.mitre.org/data/definitions/306.html) — The formal weakness definition. Useful for citing in your Section D report.

- **[CWE-598: Use of GET Request Method With Sensitive Query Strings**](https://cwe.mitre.org/data/definitions/598.html) — Why credentials go in headers, not URLs. Referenced in your assignment comments.

- **[Flask docs: Request Object**](https://flask.palletsprojects.com/en/latest/api/#flask.Request) — The official reference for `request.headers`, `request.args`, etc.


## 9. TL;DR one-liner mental model

> Every protected endpoint must ask "who are you?" **before** doing any work. Read `Authorization: Bearer \<token\>` from the request headers, parse it defensively, look up the token in your credential store, and return either the identifying username or `None`. The route reacts: `None` → `return 401`, username → proceed. Credentials go in headers, never URLs. Errors are generic, status codes are standard, and every protected route runs the check without exception.

