# Authorization & Role-Based Access Control in Flask — Walk-through/ Outline

*A tutorial-style reference for D385 Task 2 Section B, Vulnerability \#2 (Broken Authorization / CWE-862). Concepts, patterns, and the "why" — designed to prepare you before you write your solution.*


## 1. Why authentication isn't enough

Your Flask app currently has this in `require\_role()`:

```
def require\_role(username, required\_role):  
    \# INSECURE: Currently always returns True (no authorization)  
    return True
```

Even *after* you finish Vulnerability \#1 and require a valid API key, this function still lets **every authenticated user do everything**. Alice, whose role is `"user"`, could hit `/api/v1/admin/delete\_user` and remove people. Charlie the `"guest"` could view the admin user list. That's CWE-862: **Missing Authorization.**

Authentication answers "**who are you?**" Authorization answers "**what are you allowed to do?**" — and they are two completely separate questions.

An analogy: showing your ID at an airport gets you past the check-in desk. That's authentication. But it doesn't get you into the cockpit or the baggage handlers' area. Those require additional proof that your role — passenger, flight attendant, pilot, ground crew — is permitted for that specific space. That's authorization.

Skipping authorization is one of the top vulnerabilities in the industry. OWASP calls it **Broken Access Control**, and it has ranked as the \#1 web application risk in their most recent Top 10.


## 2. The core concepts (glossary)

| Term | What it means | Why it matters |
| - | - | - |
| **Authorization (AuthZ)** | Deciding whether an authenticated user is allowed to perform an action or access a resource. | The topic of this cheat sheet. |
| **Role** | A named bundle of permissions. In your app: `admin`, `user`, `guest`. | Simplifies management — assign users to roles instead of listing individual permissions. |
| **RBAC** | Role-Based Access Control. The pattern of granting access based on the user's role. | Industry-standard authorization model. |
| **Principle of Least Privilege** | Give users the *minimum* permissions needed to do their job — nothing more. | The security foundation RBAC is built on. |
| **Role hierarchy** | An ordering of roles where higher roles include the permissions of lower ones. E.g., `admin \> user \> guest`. | Lets you say "requires user role or higher" cleanly. |
| **Permission** | A specific action a user can perform (`read\_rentals`, `delete\_user`). | Roles are collections of permissions. |
| **403 Forbidden** | HTTP status: "You're authenticated, but you can't do this." | Distinct from 401 (unauthenticated). |
| **ABAC** | Attribute-Based Access Control. Access decisions use user attributes, resource attributes, and context (time, location). | More flexible than RBAC, more complex. |
| **ACL** | Access Control List. Per-resource list of who can do what. | The classic file-permissions model. |
| **Vertical privilege escalation** | A lower-privileged user accessing higher-privileged functionality. | The main risk RBAC prevents. |
| **Horizontal privilege escalation** | A user accessing *another user's* data at the same privilege level. | RBAC alone doesn't prevent this — you also need resource-ownership checks. |



## 3. The pattern you'll build — a conceptual walkthrough

The tricky decision in `require\_role()` is: what does "meets the required permission level" *mean* when you have a hierarchy like `admin \> user \> guest`?

You have two common patterns to choose from.

### Pattern 1 — Exact-match roles

```
def check\_exact\_role(user\_role, required\_role):  
    """User must have EXACTLY the required role."""  
    return user\_role == required\_role
```

Simple, but rigid. If an endpoint requires `"user"` and an `"admin"` calls it, this returns `False`. You'd need to write `check\_exact\_role(role, "user") or check\_exact\_role(role, "admin")` on every endpoint. Not great for hierarchies.

### Pattern 2 — Hierarchical ranking

```
def check\_role\_hierarchy(user\_role, required\_role):  
    """User's role must be at or above the required rank."""  
  
    \# Map roles to numeric ranks — higher is more privileged.  
    ranks = \{  
        "guest": 1,  
        "user":  2,  
        "admin": 3,  
    \}  
  
    user\_rank     = ranks.get(user\_role, 0)     \# Unknown role → rank 0 (fails everything).  
    required\_rank = ranks.get(required\_role, 0)  
  
    return user\_rank \>= required\_rank
```

This is the pattern that fits your app's `admin \> user \> guest` hierarchy. **This isn't your Task 2 answer** — it's the general shape of one valid approach. Your assignment says "Check if the user's role meets the required permission level," which is the hierarchical model.

**What each step is really doing:**

- **`ranks = \{...\}`** — A dictionary mapping each role name to a number. Numeric comparison replaces the awkward "is `admin` bigger than `user`?" string question.

- **`.get(user\_role, 0)`** — `dict.get()` with a default. If someone somehow arrives with a role like `"superadmin"` that isn't in your map, they get rank 0 — which is lower than any real role. This is **fail-closed** behavior: unknown means denied.

- **`\>=` comparison** — Higher-or-equal rank passes. `admin` (3) can access anything requiring `guest` (1), `user` (2), or `admin` (3). A `guest` (1) can only access things requiring `guest` (1).

### How the route will use it

Combined with the authentication check from the previous cheat sheet:

```
@app.route('/api/v1/admin/delete\_user', methods=\['DELETE'\])  
def delete\_user():  
    \# First, authentication: WHO is this?  
    user = require\_api\_key()  
    if not user:  
        return jsonify(\{"error": "Authentication required"\}), 401  
  
    \# Then, authorization: are they ALLOWED to do this?  
    if not require\_role(user, 'admin'):  
        return jsonify(\{"error": "Insufficient permissions"\}), 403  
  
    \# Only admins reach this point.  
    ...
```

Notice the **order**: authenticate first, then authorize. And notice the **status codes** — `401` for the first check (no valid identity), `403` for the second (identity is fine, permission is not).


## 4. Mandatory vs discretionary

### 🔴 Mandatory (violate these and it's broken)

| Rule | Why |
| - | - |
| Authorization runs on the **server**, never the client | JavaScript hiding a button doesn't stop `curl`. The check must live in server code that runs on every request. |
| Authorization runs *after* authentication | You can't authorize an unknown caller. `require\_api\_key()` first, then `require\_role()`. |
| Return `403` when authorization fails | Different from 401. Different meaning. Clients rely on the distinction. |
| Default deny — unknown roles or missing data fail closed | `.get(role, 0)` returning 0 for unknown roles is the safe default. |
| The check runs on *every* privileged endpoint | An unchecked admin endpoint is a wide-open door. |
| Never trust role information from the client | If a request body contains `\{"role": "admin"\}`, ignore it and look up the caller's role from the server-side `USERS\_DB`. |


### 🟡 Discretionary (your call, all defensible)

| Choice | Reasonable options | Notes |
| - | - | - |
| Exact-match vs. hierarchical roles | See §3 patterns 1 and 2 | Depends on your role model. |
| Whether roles have numeric ranks or are compared with sets | `ranks = \{...\}` dict + `\>=`, or `allowed = \{"admin", "user"\}` + `in` | Ranks handle hierarchy naturally; sets are more explicit. |
| Function return type | `bool`, or exception, or an "unauthorized" response object | Boolean is idiomatic for a check function. |
| Error message wording | "Insufficient permissions", "Access denied", "Forbidden" | Just stay generic — don't tell attackers exactly what role they'd need. |
| Whether the check is inline or a decorator | Inline `if not require\_role(...)` in each route, or `@require\_role('admin')` decorator | Same underlying logic, different ergonomics. |
| Whether to log denials | `logging.warning`, silent, or count for anomaly detection | Logging helps detect misuse. |
| Role names | `admin`/`user`/`guest`, or `owner`/`editor`/`viewer`, or your own | Match what your app actually models. |



## 5. Alternatives you could have used

### Option A — Hierarchical role ranking (the pattern that fits your assignment)

Numeric ranks + `\>=` comparison. See §3 pattern 2.

- ✅ Naturally models `admin \> user \> guest`.

- ✅ Easy to add new roles between existing ones (`super\_admin: 4`, `contributor: 2.5`).

- ✅ Fail-closed by default with `.get(role, 0)`.

- ❌ Assumes a strict linear hierarchy. Doesn't handle "parallel" roles well (e.g., `auditor` and `developer` at different privilege axes).

### Option B — Exact-match with role sets

```
def check\_role\_in\_set(user\_role, allowed\_roles):  
    return user\_role in allowed\_roles  
  
\# Usage:  
if not check\_role\_in\_set(user\_role, \{"admin", "user"\}):  
    return jsonify(\{"error": "Forbidden"\}), 403
```

- ✅ Explicit — no ambiguity about who has access.

- ✅ Handles non-hierarchical roles cleanly.

- ❌ Every endpoint has to spell out its allowed roles.

- ❌ Adding a new higher-privilege role means updating every endpoint.

### Option C — Permission-based (indirection)

Instead of checking roles directly, define permissions and map roles to permissions:

```
ROLE\_PERMISSIONS = \{  
    "admin": \{"read\_rentals", "write\_rentals", "delete\_user", "view\_users"\},  
    "user":  \{"read\_rentals", "write\_rentals"\},  
    "guest": \{"read\_rentals"\},  
\}  
  
def has\_permission(user\_role, permission):  
    return permission in ROLE\_PERMISSIONS.get(user\_role, set())  
  
\# Usage:  
if not has\_permission(user\_role, "delete\_user"):  
    return jsonify(\{"error": "Forbidden"\}), 403
```

- ✅ Endpoints check permissions, not roles — decoupled and more expressive.

- ✅ Changing what a role can do only touches the `ROLE\_PERMISSIONS` map.

- ✅ Closer to how real production systems model access.

- ❌ Overkill for 3 roles and a handful of endpoints.

### Option D — Decorator-based RBAC

```
from functools import wraps  
  
def require\_role(required\_role):  
    def decorator(f):  
        @wraps(f)  
        def wrapped(\*args, \*\*kwargs):  
            user = require\_api\_key()  
            if not user:  
                return jsonify(\{"error": "Authentication required"\}), 401  
            role = USERS\_DB\[user\]\['role'\]  
            if not check\_role\_hierarchy(role, required\_role):  
                return jsonify(\{"error": "Insufficient permissions"\}), 403  
            return f(\*args, \*\*kwargs)  
        return wrapped  
    return decorator  
  
@app.route('/api/v1/admin/delete\_user', methods=\['DELETE'\])  
@require\_role('admin')  
def delete\_user():  
    ...
```

- ✅ Endpoints stay clean — the decorator does the enforcement.

- ✅ Hard to forget the check when it's part of the route signature.

- ❌ Extra concepts (decorators, nested `@wraps`) to explain.

### Option E — `Flask-Principal` or `Flask-Security-Too`

Full-featured extensions that manage roles, permissions, and login state:

```
\# pip install Flask-Principal  
from flask\_principal import Principal, Permission, RoleNeed  
  
admin\_permission = Permission(RoleNeed('admin'))  
  
@app.route('/admin')  
@admin\_permission.require(http\_exception=403)  
def admin\_page():  
    ...
```

- ✅ Battle-tested, integrated with `Flask-Login`.

- ✅ Supports complex permission composition.

- ❌ Extra dependency and framework to learn.

- ❌ Hides mechanics you're supposed to demonstrate.

### Option F — Attribute-Based Access Control (ABAC)

Access decisions use *attributes* of the user, resource, and context rather than just roles:

```
def can\_access(user, resource, action, context):  
    if user.role == "admin":  
        return True  
    if action == "read" and resource.owner\_id == user.id:  
        return True  
    if context.time.hour \< 9 or context.time.hour \> 17:  
        return False   \# Business hours only for non-admins.  
    return False
```

- ✅ Extremely flexible — handles rules RBAC can't express.

- ✅ Fits complex real-world policy.

- ❌ Complexity explodes fast.

- ❌ Rules become hard to audit and reason about.

### Option G — External policy engine (Open Policy Agent, Oso, Cedar)

Move the authorization logic entirely out of your app into a dedicated policy service you query.

- ✅ Policies become versionable, auditable artifacts.

- ✅ Consistent enforcement across many services.

- ❌ Massive operational and conceptual overhead.

- ❌ Overkill for anything smaller than a mid-sized microservice architecture.


## 6. Common mistakes to avoid

- ❌ **Trusting a `role` field in the request body.** If the client sends `\{"role": "admin"\}`, ignore it. Look up the caller's role from your server-side `USERS\_DB` using the identity you got from authentication.

- ❌ **Enforcing authorization only in the UI.** Hiding an admin button in the frontend doesn't stop anyone from sending the underlying HTTP request directly. The check must run on the server.

- ❌ **Using `200 OK` with `\{"error": "forbidden"\}`.** Clients rely on status codes. Use `403`.

- ❌ **Confusing 401 and 403.** 401 = "I don't know who you are." 403 = "I know who you are, and you can't do this."

- ❌ **Fail-open defaults.** `if user\_role == 'guest': return False` and no other checks means every future new role passes by default. Prefer explicit allow lists or hierarchical `\>=`.

- ❌ **Checking roles only on some endpoints.** An unchecked administrative endpoint is a wide-open back door. Consistency matters more than the specific pattern.

- ❌ **Only preventing vertical escalation, not horizontal.** RBAC stops guests from becoming admins. It does *not* stop Alice from viewing Bob's private data — that requires a separate check that Alice owns the resource she's asking about.

- ❌ **Baking role names into endpoint logic in hundreds of places.** If you have more than a few endpoints, prefer a decorator or the permission-indirection pattern (Option C) so changes don't require touching every route.

- ❌ **Hardcoding role hierarchy in multiple places.** Define the rank map (or permission map) in one place and reference it. Duplication drifts.

- ❌ **Logging the user's password or API key when logging authorization denials.** Log the *event* and *username*, not the credential.

- ❌ **Assuming authentication implies authorization.** They're independent checks. Do both.


## 7. Quick decision guide

| Situation | Use |
| - | - |
| Class assignment with a clean role hierarchy | Hierarchical role ranking ✅ (the §3 Pattern 2 shape) |
| Small app, non-hierarchical roles | Exact-match with role sets |
| Growing app where roles' powers change often | Permission-based indirection (Option C) |
| Many protected endpoints, want DRY code | Decorator-based RBAC |
| Full Flask stack with logins, sessions, and roles integrated | Flask-Principal or Flask-Security-Too |
| Complex rules involving resource ownership, time, or context | ABAC |
| Enterprise, multi-service, policy-as-code requirements | External policy engine |



## 8. Beginner-friendly references

- **[Flask - Role Based Access Control — GeeksforGeeks**](https://www.geeksforgeeks.org/python/flask-role-based-access-control/) — Clean intro tutorial with all the basic concepts introduced from scratch.

- **[Implementing Role-Based Access Control (RBAC) in Flask — Stackademic**](https://blog.stackademic.com/implementing-role-based-access-control-rbac-in-flask-f7e69db698f6) — Focuses specifically on the `role\_required` decorator pattern with a working example.

- **[Flask Role-Based Access Control Code Sample — Auth0**](https://developer.auth0.com/resources/code-samples/api/flask/basic-role-based-access-control) — Production-quality example. Uses JWTs but the RBAC concepts translate directly.

- **[Flask RBAC Demystified — Aserto**](https://www.aserto.com/blog/flask-rbac-demystified-a-developer-s-guide) — Walks through building an RBAC system from scratch and explains the design decisions along the way.

- **[How to implement RBAC in Python — Oso**](https://www.osohq.com/learn/rbac-python) — Vendor-neutral overview of RBAC concepts with Python-specific examples. Good for the "big picture."

- **[OWASP Top 10 — A01:2021 Broken Access Control**](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) — Why this vulnerability is \#1 on OWASP's list. Excellent for citing in your Section D report.

- **[OWASP Authorization Cheat Sheet**](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) — Industry-standard reference. Covers many of the mistakes in §6 of this cheat sheet in more depth.

- **[CWE-862: Missing Authorization**](https://cwe.mitre.org/data/definitions/862.html) — The formal weakness definition. Referenced in your assignment.

- **[CWE-285: Improper Authorization**](https://cwe.mitre.org/data/definitions/285.html) — The parent category. Also cited in the code comments of `/api/v1/rentals`.

- **[NIST: Role-Based Access Control (RBAC)**](https://csrc.nist.gov/projects/role-based-access-control) — The formal RBAC model from the standards body that defined it.

- **[MDN: 403 Forbidden**](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/403) and **[MDN: 401 Unauthorized**](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401) — The definitive references for these status codes and their proper use.


## 9. TL;DR one-liner mental model

> Authentication decides *who*; authorization decides *what they can do*. Do both, in that order, on the server, on every protected endpoint. For your hierarchy, map roles to numeric ranks, look up the caller's role from server-side data (never trust the client), and require rank-at-or-above. Fail closed on unknown roles. Return `401` when they're not authenticated and `403` when they are but shouldn't be here. Least privilege is the north star: everyone gets the minimum they need, and nothing more.

