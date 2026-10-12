# Access Control Detection

## Scope

This module checks the local training application's `/profile/<id>` endpoint for IDOR and `/admin` for broken access control (missing role/privilege check).

## Detection methods

* **IDOR (`check_idor`):** authenticates as one seeded user, then requests other users' profile IDs by direct substitution. A 200 response for an ID that isn't the authenticated user's own is flagged — a correctly controlled endpoint should return 401/403 or redirect.
* **Broken access control (`check_broken_access_control`):** authenticates as a non-privileged user, then requests a path conventionally reserved for privileged roles (default `/admin`). A 200 response is flagged — the route is checking only that a session exists, not that it holds the required role.

## Interpretation

Both checks use a binary authorization-boundary probe: HTTP 200 for a resource/route the authenticated session has no legitimate claim to is treated as a confirmed finding (`VerificationStatus.CONFIRMED`), not a candidate — unlike SQL injection's error-signature matching, there's no ambiguity in a 200 where a 401/403 was expected. Any other status is recorded as a `no_finding` outcome rather than silently dropped, so a reviewer can see the boundary was actually tested.

## Remediation

* IDOR: verify server-side that the requested resource belongs to the authenticated session (or that an explicit role grants cross-user access) before returning data.
* Broken access control: check the authenticated session's role/permission explicitly (e.g. `session["is_admin"]`) before serving privileged routes — don't conflate "is logged in" with "is allowed."

## Limitation

Both checks are tailored to the supplied training app's known seed accounts and routes (`/profile/<id>`, `/admin`) and should not be treated as universal IDOR/access-control detectors. They do not attempt automatic discovery of privileged routes or ID ranges — the caller supplies `probe_ids` and `admin_path` explicitly. Unlike the SQLi module's `inspect_response()`, this module has no separate low-level primitive for use against arbitrary pre-captured responses — both checks make their own live requests, so they can't be exercised against a `crawl_map.json`-only workflow without a running target.
