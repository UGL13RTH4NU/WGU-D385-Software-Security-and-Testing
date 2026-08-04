# Password Hashing in Python —  Walkthrough

*A tutorial-style reference for D385 Task 2 Section A, Vulnerability \#2 (Plaintext Password Storage / CWE-256). Concepts, patterns, and the "why" — designed to prepare you before you write your solution, not to hand you one.*


## 1. Why hash passwords at all?

A **hash function** takes an input of any length and produces a fixed-length output that is:

- **Deterministic** — the same input always produces the same output.

- **One-way** — you can't reverse the output to recover the input.

- **Sensitive** — flipping one character in the input scrambles the whole output.

When you store a hash instead of the actual password, an attacker who steals the database only sees the hashes. They can't just read `admin123` off the disk. To log a user in, you hash whatever they type at the login form and compare the *result* to the stored hash. If the hashes match, the passwords matched.

> **Hash ≠ Encryption.** Encryption is a two-way operation — with the right key, ciphertext turns back into plaintext. Hashing has no key and no reverse. That's precisely why we use it for passwords: even the server that stores the hash can't get the original back.

Storing plaintext passwords in your source code (as `USERS\_DB` originally does) is CWE-256: **Plaintext Storage of a Password**. Every user in that dictionary is one repo leak away from being compromised on every other site where they reused their password.


## 2. The core concepts (glossary)

| Term | What it means | Why it matters |
| - | - | - |
| **Hash function** | The one-way math operation (e.g., SHA-256). | The building block. |
| **Cryptographic hash** | A hash function designed to resist attacks. | Regular hashes (`hash("hello")`) aren't safe for passwords. |
| **KDF** (Key Derivation Function) | A hash function *deliberately made slow* by repeating itself many times. PBKDF2, bcrypt, scrypt, Argon2 are KDFs. | Slowness is a feature — it's what stops brute-force. |
| **Salt** | A random value added to the password before hashing. | Stops attackers from using precomputed tables ("rainbow tables") and stops two users with the same password from producing the same hash. |
| **Iterations / work factor** | How many times the KDF repeats internally. | Higher = slower to compute = slower to attack. |
| **Pepper** | A *secret* value added to every password (kept outside the database, e.g., in an env var). | Optional extra defense. Not a substitute for salt. |
| **Rainbow table** | A precomputed lookup of common passwords to their hashes. | Salting defeats them, which is why salt is mandatory. |
| **Timing-safe comparison** | A byte-by-byte comparison that always takes the same amount of time. | Prevents attackers from measuring comparison duration to guess the hash. |



## 3. The pattern you'll build — a conceptual walkthrough

The general shape of password hashing is a sequence of four steps. **This isn't your Task 2 solution** — it's a teaching outline showing the pieces you'll assemble into a function.

### Step 1 — Encode the password as bytes

```
password\_bytes = plaintext.encode('utf-8')
```

Cryptographic hash functions in Python operate on `bytes`, not `str`. If you pass a string in directly, you'll get `TypeError: Strings must be encoded before hashing`. UTF-8 is the safe default — it can represent every Unicode character without loss.

### Step 2 — Generate cryptographically secure salt

```
salt = os.urandom(SALT\_LENGTH\_BYTES)   \# 16 is a common minimum
```

`os.urandom()` reads from the operating system's cryptographically secure random pool (`/dev/urandom` on Linux, `BCryptGenRandom` on Windows). **Do not use the `random` module** — it's fast but predictable and unsuitable for anything security-related. The `secrets` module (`secrets.token\_bytes(16)`) is an equally good alternative and arguably clearer in intent.

**A key design question:** where does the salt live?

- **Per-user (real-world best practice):** Generate a fresh salt each time you hash a new password, and store it alongside the hash for that user. Two users with the same password get different hashes.

- **Module-level (simpler, weaker):** One salt for the whole application. All users with the same password get the same hash. This still beats plaintext and still passes rainbow-table defense, but it's not what production code does.

The rubric doesn't require the per-user pattern, but understanding the tradeoff matters for the conceptual grade and for Section D.

### Step 3 — Apply a KDF with a work factor

The call shape for the standard-library KDF:

```
hashlib.pbkdf2\_hmac(  
    HASH\_ALGORITHM,      \# e.g., 'sha256' — the inner hash  
    PASSWORD\_BYTES,      \# from Step 1  
    SALT,                \# from Step 2  
    ITERATION\_COUNT      \# the work factor — see below  
)
```

**Why "work factor"?** A single SHA-256 pass is microseconds — meaning an attacker with a stolen database can try billions of password guesses per second. PBKDF2's job is to *deliberately slow that down* by running the inner hash thousands of times. The user waits an imperceptible ~100 milliseconds; an attacker's brute-force campaign takes years instead of hours.

**How many iterations?** OWASP's current guidance for PBKDF2-SHA256 is a minimum of **600,000 iterations**. This roughly targets 100 ms on modern hardware. Numbers below that are outdated; higher is fine but user-experience-noticeable.

### Step 4 — Store the result

The output of `pbkdf2\_hmac` is raw bytes. You now need to store two things per user:

1. The **hash** (the output of Step 3)

2. The **salt** you used in Step 2 (so you can repeat the calculation at login time)

If you're using per-user salts, the common convention is to concatenate them (`salt + hash`) into a single stored value. If you're using a module-level salt, you only need to store the hash — the salt lives in the code.

**One structural note relevant to your assignment:** the `USERS\_DB` dictionary keys will need updating. The plaintext version uses `"password"` as the key. Once you're storing hashes, that key name is misleading. Renaming it to something like `"password\_hash"` is a small but important change — and any test that reads from `USERS\_DB` will need to match.

### Putting the steps together

Your `hash\_password()` function will combine Steps 1–3 into a callable. You'll then rebuild `USERS\_DB` so that each user's stored value is `hash\_password("their\_password")` instead of the plaintext string. There are a few structural choices to make:

- Does `hash\_password()` take one argument (the password) or two (password + salt)?

- Does it return raw bytes, a hex string, or `salt + hash` concatenated?

- Is the salt generated inside the function or passed in?

Any of these can be right. Pick a shape and be consistent.


## 4. Mandatory vs discretionary

### 🔴 Mandatory (violate these and it's broken)

| Rule | Why |
| - | - |
| Encode the password as bytes before hashing | `hashlib` won't accept a `str`. |
| Use a **cryptographic** hash (SHA-256, SHA-512, etc.), never MD5 or SHA-1 alone | MD5 and SHA-1 are broken. |
| Use a KDF (PBKDF2, bcrypt, scrypt, Argon2), not a bare hash | A single SHA-256 pass is way too fast for password protection. |
| Use a **salt** | Without it, identical passwords produce identical hashes → rainbow-table attack. |
| Use a **cryptographically secure** random source for the salt (`os.urandom` or `secrets.token\_bytes`) | `random.random()` is predictable. |
| Store the salt somewhere you can retrieve it | You need it again to verify the password later. |
| Never store the plaintext password anywhere | Not in the database, not in logs, not in error messages. |


### 🟡 Discretionary (your call, within safe ranges)

| Choice | Reasonable options | Notes |
| - | - | - |
| Hash algorithm inside PBKDF2 | `'sha256'`, `'sha512'` | SHA-256 is the common default. SHA-512 is fine but produces longer output. |
| Iteration count | 600,000+ for SHA-256, 210,000+ for SHA-512 | Higher is safer but slower. Tune to ~100 ms on your target hardware. |
| Salt length | 16 bytes minimum, 32 is also common | Longer is fine; shorter than 16 is not. |
| Per-user vs. module-level salt | Per-user in production, either is acceptable for the assignment rubric | See Step 2 discussion. |
| Which KDF entirely | PBKDF2, bcrypt, scrypt, Argon2id | See §6 for trade-offs. |
| Whether to add a pepper | Yes / No | Nice-to-have extra layer, not required. |
| Output encoding for storage | Raw bytes, hex, base64 | Cosmetic. Pick one and be consistent. |
| Function and variable names | Whatever reads clearly | Style. |



## 5. Verifying a password later

Hashing is only half the story. When someone logs in, you need to *check* their password. The assignment rubric doesn't strictly require you to write a verification function, but understanding it is essential for the concepts and for the report.

The general shape:

```
def verify(entered\_password, stored\_hash, salt):  
    """Teaching skeleton — not the assignment answer."""  
    candidate = hashlib.pbkdf2\_hmac(  
        HASH\_ALGORITHM,  
        entered\_password.encode('utf-8'),  
        salt,  
        ITERATION\_COUNT       \# MUST match the count used at signup  
    )  
    return hmac.compare\_digest(candidate, stored\_hash)
```

**Why `hmac.compare\_digest` instead of `candidate == stored\_hash`?** Normal `==` short-circuits — it stops comparing as soon as it finds a difference. An attacker can measure how long the comparison takes and learn how many bytes of the hash they got right. `compare\_digest` always takes the same amount of time regardless of where the mismatch is. This is called a **timing-safe comparison** and it's the mandatory practice for any secret comparison.

The other thing to notice: verification must use **the exact same salt, algorithm, and iteration count** that were used at signup. If any of those change between signup and verification, the passwords won't match even when they should.


## 6. Alternatives you could have used

### Option A — `hashlib.pbkdf2\_hmac` (the standard-library option)

The assignment's intended path. Shape sketched in §3.

- ✅ Standard library — no `pip install`.

- ✅ FIPS 140 compliant (matters in regulated industries).

- ✅ Simple to reason about.

- ❌ CPU-only — a determined attacker with a GPU farm can still burn through it faster than memory-hard alternatives.

### Option B — `bcrypt`

Interface shape:

```
\# pip install bcrypt  
import bcrypt  
  
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))  
bcrypt.checkpw(password.encode('utf-8'), hashed)   \# returns True/False
```

- ✅ Battle-tested since 1999.

- ✅ Salt is built into the output — no separate storage needed.

- ✅ Very hard to misuse.

- ❌ Silently truncates passwords longer than 72 bytes.

- ❌ Not FIPS-approved.

### Option C — `argon2-cffi` (Argon2id) — OWASP's current top pick

Interface shape:

```
\# pip install argon2-cffi  
from argon2 import PasswordHasher  
  
ph = PasswordHasher()  
hashed = ph.hash(password)              \# produces a self-contained string  
ph.verify(hashed, password)             \# raises exception if it doesn't match
```

- ✅ 2025 gold standard, memory-hard (resistant to GPU/ASIC attacks).

- ✅ Salt, algorithm, and parameters all embedded in the output string.

- ❌ Extra dependency.

- ❌ Not FIPS-approved.

### Option D — `werkzeug.security` (bundled with Flask)

Interface shape:

```
from werkzeug.security import generate\_password\_hash, check\_password\_hash  
  
hashed = generate\_password\_hash(password, method='pbkdf2:sha256:600000')  
check\_password\_hash(hashed, password)   \# returns True/False
```

- ✅ Zero extra dependencies since Flask already installs Werkzeug.

- ✅ Handles salt generation, storage format, and verification for you.

- ✅ The stored string includes the method, iteration count, and salt — self-contained.

If you were rewriting this from scratch and wanted the smallest, cleanest solution, **this is the option** given Flask is already in play.

### Option E — `passlib` (high-level convenience layer)

Interface shape:

```
\# pip install passlib  
from passlib.hash import pbkdf2\_sha256  
  
hashed = pbkdf2\_sha256.hash(password)  
pbkdf2\_sha256.verify(password, hashed)
```

Wraps most of the above algorithms behind a uniform API. Good if you want the freedom to swap algorithms later.


## 7. Common mistakes to avoid

- ❌ **Using MD5 or SHA-1 as the whole solution.** They're fast, unsalted, and broken.

- ❌ **A single unsalted SHA-256.** Still too fast; still vulnerable to rainbow tables.

- ❌ **Encrypting the password instead of hashing.** Encryption is reversible; if someone gets the key, every password is exposed.

- ❌ **The same salt for every user across a production system.** Passes the rubric here, but bad practice at scale.

- ❌ **Storing the salt secretly.** Salt isn't a secret; it just needs to be *unique*. Store it right next to the hash.

- ❌ **Rolling your own algorithm.** Cryptography is a landmine field. Use vetted libraries.

- ❌ **Comparing hashes with `==`.** Use `hmac.compare\_digest` (or the library's own verifier).

- ❌ **Forgetting to `.encode()` the password.** You'll get a `TypeError`.

- ❌ **Keeping the plaintext `"password"` key name after switching to hashes.** Any test or code that reads the field will still say `"password"`. Rename it — `"password\_hash"` is a common convention.

- ❌ **Hardcoding the iteration count in multiple places.** If you ever need to raise it, you'll want one place to change.


## 8. Quick decision guide

| Situation | Use |
| - | - |
| Class assignment with only stdlib allowed | `hashlib.pbkdf2\_hmac` ✅ |
| Regulated environment (FIPS, HIPAA, PCI) | `hashlib.pbkdf2\_hmac` |
| Flask app, small dependency footprint | `werkzeug.security.generate\_password\_hash` |
| Any new production app, no regulatory constraints | `argon2-cffi` (Argon2id) |
| Existing codebase using bcrypt | `bcrypt` — keep it, still safe |



## 9. Beginner-friendly references

- **[How To Hash Passwords In Python — Nitratine**](https://nitratine.net/blog/post/how-to-hash-passwords-in-python/) — Clean walk-through of `pbkdf2\_hmac` with each parameter explained.

- **[Password hashing in Python with pbkdf2 — Simon Willison's TIL**](https://til.simonwillison.net/python/password-hashing-with-pbkdf2) — Shows a `hash\_password` / `verify\_password` pair with a self-contained storage format (algorithm$iterations$salt$hash). Excellent template for understanding the full lifecycle.

- **[Python hashing and salting — DEV Community**](https://dev.to/shittu_olumide_/python-hashing-and-salting-4dea) — Beginner-friendly intro that also covers MD5/SHA1/SHA-256 for context on *why* PBKDF2 exists.

- **[OWASP Password Storage Cheat Sheet**](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — The industry-standard reference. This is where "600,000 iterations for PBKDF2-SHA256" comes from. Bookmark it.

- **[Python `hashlib` docs**](https://docs.python.org/3/library/hashlib.html#hashlib.pbkdf2_hmac) — The official reference for the exact function you'll call.

- **[Python `secrets` module docs**](https://docs.python.org/3/library/secrets.html) — Covers `secrets.token\_bytes` and `secrets.compare\_digest`, both of which are drop-in improvements over `os.urandom` and `hmac.compare\_digest` respectively.

- **[CWE-256: Plaintext Storage of a Password**](https://cwe.mitre.org/data/definitions/256.html) — The formal weakness definition. Useful for citing in your Section D report.

- **[CWE-916: Use of Password Hash With Insufficient Computational Effort**](https://cwe.mitre.org/data/definitions/916.html) — The related weakness that PBKDF2's iteration count defends against. Also good citation material.


## 10. TL;DR one-liner mental model

> Take the password, mix it with a random salt, and put it through a deliberately slow one-way function (PBKDF2 / bcrypt / Argon2). Store the hash **and** the salt. To verify later, repeat the process on the entered password and compare with `hmac.compare\_digest`. Never store the plaintext, never use a bare SHA-256, never use `==`.

