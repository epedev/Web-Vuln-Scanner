# SQL Injection Detection

## Scope

This module checks the local training application's `/login` endpoint and provides a helper for recognizing database error signatures.

## Detection methods

* **Behavior comparison:** compares a deliberately invalid baseline login with the documented SQL injection test and observes the HTTP status and redirect.
* **Error signature inspection:** searches a response for common database error patterns.

## Interpretation

An authentication-related redirect is classified as probable behavior consistent with an authentication bypass. Database error signatures are candidates that require investigation.

## Remediation

Use parameterized SQL queries, securely hash passwords, and avoid exposing internal database errors in HTTP responses.

## Limitation

The login check is tailored to the supplied training app and should not be treated as a universal SQL injection detector.
