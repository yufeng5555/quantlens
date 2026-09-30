"""Dormant Gate E Stop B2b plan-anchor issuance authority package.

An independently packaged control-plane authority: it authenticates one signed
CONTROL_PLANE_REGISTRAR issue request, validates its complete validation-plan-v3,
signs one validation-plan-anchor-v1 and durably persists the exact bytes in an
authority-only SQLite database before returning them.

This package intentionally re-exports nothing, reads no configuration, opens no
database, loads no key and starts no service at import time.  Explicit construction
in ``authority_v1`` performs every preflight; ``service_v1.main()`` is the only
entry point that reads configuration, and no acceptance flow invokes it.
"""
