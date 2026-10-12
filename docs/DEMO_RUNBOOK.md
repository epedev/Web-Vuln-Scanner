# Graduation demo runbook

Use this checklist for a live presentation or screen recording. Do **not** claim a video exists unless you have recorded one.

## 0. Environment (once)

```bash
cd Web-Vuln-Scanner
python3 -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
vulnsight doctor
```

Expected: `RESULT: ready`.

## 1. Clean lab state

```bash
# Terminal A
python target_app/app.py
```

In another shell (lab must already be running):

```bash
curl -X POST http://127.0.0.1:5001/_lab/reset
```

Confirm home page opens at http://127.0.0.1:5001.

## 2. Full scanner run

```bash
# Terminal B
vulnsight scan --target http://127.0.0.1:5001 --output ./reports -v
```

Show:

- Startup scope line (`lab-loopback`)
- Per-module status lines
- `reports/vulnsight_report.html` and `reports/findings.json`

## 3. Walk each vulnerability class

| Class | Vulnerable demo | Secure negative control | What to say |
|-------|-----------------|-------------------------|-------------|
| Reflected XSS | `/reflect?q=<b>x</b>` | `/encoded?q=<b>x</b>` | Raw reflection vs context encoding |
| Stored XSS | POST `/comment` then `/comments` | Reset clears store | Persist + render path |
| SQLi | login `admin' -- ` / any password | `/login-secure` rejects | Parameterized queries |
| Cmd injection (simulated) | POST `/ping` host `127.0.0.1; printf REDOPS_CMD_TEST` | Lab does **not** run a shell | Unsafe concat pattern only |
| IDOR | login alice → `/profile/2` | `/profile-secure/2` → 403 | Object-level authz |
| Broken AC | alice → `/admin` 200 | `/admin-secure` → 403 | Role checks |

## 4. Report narration

In the HTML report, for one finding of each class cover:

1. Verification status vs confidence vs severity
2. Sanitized evidence
3. Root cause
4. Remediation / secure-code idea
5. CWE / OWASP
6. Limitations (partial coverage, optional browser verify, simulated cmd injection)

## 5. Safety talking points

- Explicit `--target` required
- Default scope is loopback only
- Crawler discovery ≠ authorization
- `--allow-external` is opt-in and warned

## 6. Screen-recording checklist

- [ ] Show `vulnsight doctor`
- [ ] Show lab home + reset
- [ ] Show one vulnerable vs secure pair live in browser
- [ ] Run `vulnsight scan` end-to-end
- [ ] Open HTML report executive summary
- [ ] Open one detailed finding with remediation
- [ ] State limitations honestly (DOM XSS experimental, no full OWASP Top 10 claim)
- [ ] Stop lab (`Ctrl+C`)

## 7. Common demo failures

| Symptom | Fix |
|---------|-----|
| Port 5001 busy | `VULNSIGHT_LAB_PORT=5002 python target_app/app.py` and retarget scan |
| Stale stored XSS | `curl -X POST http://127.0.0.1:5001/_lab/reset` |
| Scope error | Use `http://127.0.0.1:5001`, not a public hostname |
| Missing vulnsight | Activate venv; `pip install -e ".[dev]"` |
