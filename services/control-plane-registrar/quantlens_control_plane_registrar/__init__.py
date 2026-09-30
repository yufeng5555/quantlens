"""QuantLens control-plane registrar service package.

The registrar is the third control-plane process beside the two Gate E
authorities: it alone holds the CONTROL_PLANE_REGISTRAR role keys, converts
worker registrar-protocol envelopes into signed authority requests, and
enforces the one-issue-per-run control-plane law. It never holds an authority
signing key and never holds the worker's evaluator key, so no single process
can mint itself fresh final-holdout access.
"""
