# Expected lab findings (reference)

Against `target_app` on `http://127.0.0.1:5001`, a full `vulnsight scan` should typically report:

| Class | Endpoint | Notes |
|-------|----------|-------|
| Reflected XSS | `/reflect?q=` | Candidate/probable unless browser verify confirms |
| Stored XSS | `/comment` → `/comments` | Marker reflection on render page |
| SQL injection | `POST /login` | Auth bypass via `admin' -- ` |
| Command injection (simulated) | `POST /ping` | Marker `REDOPS_CMD_TEST` in response |
| IDOR | `GET /profile/<id>` | Alice session reads Bob/Admin profiles |
| Broken access control | `GET /admin` | Non-admin session gets HTTP 200 |

Negative controls (should **not** produce equivalent confirmed findings):

- `/encoded` — HTML-escaped reflection
- `/login-secure` — parameterized SQL
- `/profile-secure/<id>` — ownership check
- `/admin-secure` — role check
