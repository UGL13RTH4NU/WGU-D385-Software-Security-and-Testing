# Environment Variables for Secrets —  Walkthrough

*A tutorial-style reference for D385 Task 2 Section A, Vulnerability \#1 (Hardcoded Credentials / CWE-798). Concepts, patterns, and the "why" — designed to prepare you before you write your solution, not to hand you one.*


## 1. Why not just hardcode credentials?

**Hardcoded secrets** are values like passwords, API keys, and session keys written directly into source code as string literals. It's tempting because it works — the code runs, the tests pass. But it creates several serious problems that don't show up until it's too late:

- **Version control history is forever.** The moment you commit an API key literal, that secret is in the git history. Even if you delete it in the next commit, `git log` still shows it. Public repos get scanned by bots within minutes.

- **Everyone with code access sees every secret.** A contractor who needs to fix one bug also gets your production database password.

- **Rotating a credential means a code change.** If the key leaks, you can't just swap it — you have to edit, commit, review, and deploy. That's minutes to hours of exposure during an active incident.

- **Same code, different environments.** Your dev, staging, and production databases have different passwords. Hardcoding forces you to maintain three versions of the code or write branching logic.

- **CWE-798 / CWE-259.** These are formally cataloged software weaknesses. Static analyzers like Bandit and flake8 flag them automatically — which is exactly how they showed up in your Task 2 reports.

The fix is to keep credentials **outside the code** and read them at runtime.


## 2. The core concepts (glossary)

| Term | What it means | Why it matters |
| - | - | - |
| **Environment variable** | A named value stored by the operating system, available to any process the OS starts. | Standard, cross-platform way to feed config into a program without touching its code. |
| **`os.environ`** | Python's dictionary-like view into the environment variables of the currently running process. | Your primary read/write interface. |
| **Secret** | Any value that would cause harm if leaked — passwords, API keys, session-signing keys, tokens. | Determines *how carefully* you need to store it. |
| **12-Factor App** | An influential design guide that says config (including secrets) should live in the environment, not in code. | This is the "why" behind env vars being the default. |
| **`.env` file** | A plain-text file (usually in your project folder) that lists env vars for local development. Loaded at startup by a library like `python-dotenv`. | Convenient for dev; **never committed** to git. |
| **Secrets manager** | A dedicated service (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) that stores secrets and hands them out with access controls, auditing, and rotation. | The production-grade answer. |
| **Fallback / default value** | What your program uses when the env var isn't set. | Design choice — sometimes safe (dev-friendly), sometimes dangerous (silent misconfig). |



## 3. The pattern you'll build — a conceptual walkthrough

Here's the general shape of externalizing a secret. **This isn't your Task 2 solution** — it's a teaching skeleton showing the pieces you'll assemble.

### Step 1 — Choose your access method

Python gives you three ways to read an environment variable, and they behave differently when the variable is missing:

```
os.environ\['SOME\_VAR'\]              \# raises KeyError if missing  
os.environ.get('SOME\_VAR')          \# returns None if missing  
os.environ.get('SOME\_VAR', 'default')   \# returns the default if missing  
os.getenv('SOME\_VAR', 'default')    \# identical to .get() — just a shorter name
```

**Which do you pick?** That depends on whether you want the missing case to be an *event you handle* or a *silent substitution.* If the missing case matters enough to log or react to, `os.environ\['NAME'\]` + `try/except KeyError` gives you a natural place to do that. If you just want a quiet default, `.get()` is more concise.

### Step 2 — Choose your fallback strategy

When the variable is missing, you have three defensible responses (§5 covers each in more depth):

- **Generate a safe substitute** — good when any random value of the right shape works (session keys).

- **Fail-safe null** — good when there's no valid substitute and downstream code should refuse to work.

- **Refuse to start** — good when the app can't do its job without the value.

### Step 3 — Handle the missing case explicitly

The general shape for a security-oriented try/except pattern:

```
try:  
    value = os.environ\['SECRET\_NAME'\]  
except KeyError:  
    value = FALLBACK\_STRATEGY           \# one of the three above  
    logging.warning("SECRET\_NAME not set — used fallback.")
```

**What each line is really doing:**

- **`os.environ\['SECRET\_NAME'\]`** — Bracket syntax. Behaves like a dictionary lookup: missing keys raise `KeyError`. That's *intentional* — you want to know when a variable is missing so you can react.

- **`except KeyError:`** — The specific exception `os.environ\[\]` raises when the variable isn't set. Catching `KeyError` specifically (not a bare `except:`) is best practice — you only handle the case you're actually expecting, so unrelated bugs still surface.

- **The fallback assignment** — Where you apply your chosen strategy from Step 2.

- **`logging.warning(...)`** — Records that the fallback fired. Shows up in the log file so you (or an evaluator) can see the code is functioning as designed rather than silently swallowing a missing variable. **Never log the secret value itself** — log the event.

### Step 4 — Comment out the old hardcoded line

The assignment's Section A3 requirement: don't delete the original insecure code. Comment it out so evaluators can see what was replaced. In practice this means something like:

```
\# app.some\_secret = 'the\_original\_hardcoded\_string'   \# INSECURE (CWE-798) — replaced below
```

This isn't a security requirement — it's a grading one. Deleting the line would leave the evaluator hunting for what changed.


## 4. Mandatory vs discretionary

### 🔴 Mandatory (violate these and the fix is broken)

| Rule | Why |
| - | - |
| Secrets must not be string literals in source code | The whole point of the exercise. |
| Read the secret from *somewhere outside the code* at runtime | Env var, config file, secrets manager — any of these works. |
| Handle the case where the value is missing | Otherwise you get a cryptic runtime crash later, or worse, silent misbehavior. |
| Catch the *specific* exception (`KeyError`), not a bare `except:` | Bare excepts hide unrelated bugs. |
| Never log or print the secret's value | Log the *event* ("SECRET\_NAME loaded"), not the value. |


### 🟡 Discretionary (your call, all defensible)

| Choice | Reasonable options | Notes |
| - | - | - |
| Bracket vs. `.get()` | `os.environ\['KEY'\]` (raises) or `os.environ.get('KEY', default)` (returns default) | See §5 — different semantics, both valid. |
| Fallback value strategy | Generated safe value, `None`, or hard failure (`raise`) | Depends on whether the app can meaningfully run without it. |
| Where to store the env vars in dev | Shell export, `.env` file, IDE run config | All fine for local dev. |
| Where to store them in production | Cloud secrets manager, container orchestrator, CI/CD injection | Choose based on your platform. |
| Whether to log the fallback | `logging.warning`, `logging.error`, silent | Logging aids debugging and evaluator visibility. |
| Variable naming convention | `SCREAMING\_SNAKE\_CASE` in the environment, whatever you like in Python | Environment side is a strong convention. |


### The bracket vs. `.get()` question specifically

The rubric example shows something like `os.environ.get('SOME\_VAR', fallback\_expression)`. The try/except form is equivalent in functional outcome but expresses different *intent*:

- **`.get()` with default** — "If missing, quietly substitute the default. No big deal."

- **`try/except KeyError`** — "If missing, this is an event I want to acknowledge, log, and react to."

For a security-focused assignment where a grader wants to see you handling missing secrets deliberately, the try/except form arguably reads better. It also gives you a natural place to log the fallback, which `.get()` doesn't do without an extra line of code. Either is defensible.


## 5. Fallback strategy — three legitimate approaches

When a required env var is missing, you have three defensible responses. Each is right in a different situation.

### A. Generate a safe fallback

```
try:  
    value = os.environ\['SESSION\_SIGNING\_KEY'\]  
except KeyError:  
    value = secrets.token\_hex(32)  
    logging.warning("SESSION\_SIGNING\_KEY not set — generated fallback.")
```

- ✅ App keeps running, developer isn't blocked.

- ✅ The fallback is cryptographically strong (not `"default"` or `"changeme"`).

- ❌ Existing signed sessions/cookies become invalid on every restart.

- ❌ In production, this would silently hide a serious misconfiguration.

**Use when:** the value can be any random string of the right form (session keys, CSRF tokens). Notice `secrets.token\_hex(32)` produces 32 random bytes formatted as a 64-character hexadecimal string — perfectly suited for a Flask session-signing key.

### B. Fail-safe null

```
try:  
    value = os.environ\['DB\_PASSWORD'\]  
except KeyError:  
    value = None  
    logging.warning("DB\_PASSWORD not set — using None.")
```

- ✅ Downstream code will fail loudly and predictably.

- ✅ No risk of accidentally connecting to the wrong resource with a "default" credential.

- ❌ The failure happens later, further from the actual cause.

**Use when:** there's no safe default value (real credentials have no substitute).

### C. Refuse to start

```
try:  
    value = os.environ\['DB\_PASSWORD'\]  
except KeyError:  
    raise RuntimeError("DB\_PASSWORD is required — refusing to start.")
```

- ✅ Fails immediately at startup, clearly, with a helpful message.

- ✅ Impossible for the app to run in a misconfigured state.

- ❌ Zero developer forgiveness — no dev environment without setting the var.

**Use when:** the app cannot meaningfully do anything without the value. This is the production-recommended pattern.


## 6. Alternatives you could have used

### Option A — `os.environ\[\]` with try/except (the standard-library security-focused option)

Sketched in §3. Best when you want explicit control over the missing case and a natural place to log or react.

- ✅ Standard library only.

- ✅ Explicit intent — you're saying "I know this might not be set, and here's what I'll do."

- ✅ Room to add logging or complex fallback logic.

- ❌ More verbose than the alternatives.

### Option B — `os.environ.get()` with default

Interface shape:

```
value = os.environ.get('API\_KEY', None)
```

- ✅ One line.

- ✅ Clear and idiomatic Python.

- ❌ No natural place to log or react to the missing value.

- ❌ Encourages silent defaults that mask misconfigurations.

### Option C — `os.getenv()`

Interface shape:

```
value = os.getenv('API\_KEY')                  \# Returns None if missing.  
value = os.getenv('API\_KEY', 'safe\_default')  \# Or a default.
```

Functionally identical to `os.environ.get()`. Some people find `os.getenv()` reads more naturally because it looks like a function, not a dictionary access. Pure style preference.

### Option D — `.env` file with `python-dotenv`

Interface shape:

```
\# pip install python-dotenv  
from dotenv import load\_dotenv  
import os  
  
load\_dotenv()   \# Reads .env file in current directory into os.environ.  
  
value = os.environ\['API\_KEY'\]
```

With a `.env` file like:

```
API\_KEY=sk\_live\_abc123  
DB\_PASSWORD=hunter2
```

- ✅ No more editing shell profiles or IDE run configs.

- ✅ Easy to share a `.env.example` template with teammates.

- ✅ Very common in Flask/FastAPI/Django projects.

- ❌ **Must add `.env` to `.gitignore` or you're right back where you started.**

- ❌ Extra dependency (though a tiny one).

- ⚠️ Only for local dev — production shouldn't rely on `.env` files.

### Option E — Config file (`config.py`, YAML, JSON, TOML)

Interface shape:

```
\# config.py — kept OUT of git via .gitignore  
API\_KEY = "sk\_live\_abc123"  
  
\# app.py  
from config import API\_KEY
```

- ✅ Familiar pattern from many frameworks.

- ✅ Can hold complex nested settings, not just strings.

- ❌ Still a file on disk with plaintext secrets.

- ❌ Easy to accidentally commit if `.gitignore` is misconfigured.

Same idea for YAML/JSON/TOML files — just different format. Django settings modules and Flask instance configs work this way.

### Option F — `pydantic-settings` (typed config with validation)

Interface shape:

```
\# pip install pydantic-settings  
from pydantic\_settings import BaseSettings  
  
class Settings(BaseSettings):  
    api\_key: str  
    db\_password: str  
    flask\_secret\_key: str  
  
    class Config:  
        env\_file = '.env'  
  
settings = Settings()   \# Raises if any required field is missing.
```

- ✅ Automatic type coercion (env vars are strings; `int` fields become integers).

- ✅ Fails at startup with clear errors if anything's missing.

- ✅ IDE autocomplete on `settings.api\_key`.

- ❌ Bigger dependency, more concepts to learn.

### Option G — Cloud secrets manager (production answer)

Interface shape (AWS Secrets Manager):

```
\# pip install boto3  
import boto3, json  
  
client = boto3.client('secretsmanager')  
response = client.get\_secret\_value(SecretId='prod/myapp/api\_key')  
API\_KEY = json.loads(response\['SecretString'\])\['api\_key'\]
```

- ✅ Never touches disk on the app server.

- ✅ Auditable — every read is logged.

- ✅ Rotatable — swap the secret without redeploying the app.

- ✅ Fine-grained IAM access control.

- ❌ Cloud-specific (equivalents exist for Azure, GCP, Vault).

- ❌ Costs money per API call.

- ❌ Latency on startup.

Similar options: **Azure Key Vault**, **Google Secret Manager**, **HashiCorp Vault**, **Kubernetes Secrets**.

### Option H — CI/CD environment injection (deployment-time)

```
\# GitHub Actions example  
env:  
  API\_KEY: $\{\{ secrets.API\_KEY \}\}
```

The CI/CD system holds the secret and injects it as an env var when it deploys or runs the app. Your Python code just does `os.environ\['API\_KEY'\]` — no library, no manager code. This is how a lot of real production apps actually work.


## 7. Common mistakes to avoid

- ❌ **Committing `.env` to git.** Add it to `.gitignore` on day one. If you already committed it, rotate every secret in it — deleting the file later doesn't remove it from history.

- ❌ **Bare `except:` clauses.** Catches every exception, including `KeyboardInterrupt`, hiding bugs and making debugging miserable. Always catch the specific type.

- ❌ **Silent defaults for critical secrets.** `os.environ.get('DB\_PASSWORD', '')` connecting to the database with an empty password is worse than crashing loudly.

- ❌ **Insecure default values.** `secrets.token\_hex(32)` — good. `"changeme"` — a landmine. `"default\_password"` — a landmine you'll deploy to production.

- ❌ **Logging the secret itself.** Never `logging.info(f"Loaded API key: \{API\_KEY\}")`. Log the *event* ("API\_KEY loaded") not the *value*.

- ❌ **Using `print()` instead of `logging`.** `print` goes to stdout only. `logging` writes to configurable outputs (files, syslog, cloud log services) with severity levels and timestamps.

- ❌ **Assuming env vars are typed.** They aren't. Every env var comes out of `os.environ` as `str`. If you need an integer or boolean, convert it yourself: `int(os.environ\['PORT'\])`.

- ❌ **Reusing prod secrets in dev.** Every environment gets its own credentials. That's half the reason you moved to env vars in the first place.

- ❌ **Deleting the original hardcoded line entirely.** The assignment specifically asks you to comment it out so evaluators can see the before/after.


## 8. Quick decision guide

| Situation | Use |
| - | - |
| Class assignment with only stdlib allowed | `os.environ` + try/except ✅ |
| Local dev with several env vars to juggle | `.env` file + `python-dotenv` |
| Small app that needs typed config with validation | `pydantic-settings` |
| Production on AWS/Azure/GCP | Cloud secrets manager |
| Production on Kubernetes | Kubernetes Secrets (mounted as env vars) |
| CI/CD deployments | Platform's built-in secrets (GitHub Actions, GitLab CI, etc.) |
| Bare-metal or VM production | `systemd` environment file, or env vars set at process launch |



## 9. Beginner-friendly references

- **[Python Environment Variables: What You Need to Know — DataCamp**](https://www.datacamp.com/tutorial/python-environment-variables) — Beginner-friendly walkthrough of `os.environ` and `python-dotenv` with runnable examples.

- **[Python Environment Variables (Env Vars): A Primer — Vonage Developer**](https://developer.vonage.com/en/blog/python-environment-variables-a-primer) — Covers five different ways to set env vars, from shell exports to `.env` files. Excellent for understanding the landscape.

- **[Python Env Vars: Complete Guide — Codecademy**](https://www.codecademy.com/article/python-environment-variables) — Focused specifically on the `.env` + `python-dotenv` workflow.

- **[Python `os.environ` docs**](https://docs.python.org/3/library/os.html#os.environ) — Official reference. Short and worth reading.

- **[Python `secrets` module docs**](https://docs.python.org/3/library/secrets.html) — Explains `token\_hex`, `token\_bytes`, and `token\_urlsafe` — where the safe-fallback function comes from.

- **[Python `logging` HOWTO**](https://docs.python.org/3/howto/logging.html) — The official beginner tutorial for the logging module.

- **[The Twelve-Factor App — Config**](https://12factor.net/config) — One page. Explains *why* the industry moved to env-var-based config. Foundational reading for any serious backend developer.

- **[CWE-798: Use of Hard-coded Credentials**](https://cwe.mitre.org/data/definitions/798.html) — The formal weakness definition. Useful for citing in your Section D report.

- **[CWE-259: Use of Hard-coded Password**](https://cwe.mitre.org/data/definitions/259.html) — The related weakness Bandit flags with `B105`. Also good citation material.


## 10. TL;DR one-liner mental model

> Keep the *code* generic and the *secrets* in the environment. Read them at runtime with `os.environ`, catch `KeyError` for missing values, and pick your fallback strategy on purpose — generate a safe random value when any random value will do, use `None` when it must fail loudly, or `raise` when the app can't function without it. Never commit a `.env` file. In production, use a real secrets manager.

