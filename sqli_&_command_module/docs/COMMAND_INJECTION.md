# OS Command Injection Detection

## Scope

This module checks the intentionally vulnerable local Flask application's `/ping` endpoint.

## Detection method

The detector submits a normal baseline request and a controlled request containing a unique, harmless output marker. It checks whether the marker appears in the HTTP response.

## Interpretation

Observing the marker supports the conclusion that input reached a shell-executed command in the tested application. The finding applies to the behavior observed in this lab.

## Remediation

Avoid `shell=True` when processing user input. Use `subprocess.run` with an argument list and `shell=False`, validate hostnames or IP addresses, and handle errors safely.

## Limitation

This marker-based check is specific to the training app's behavior and cannot detect every form of command injection.
