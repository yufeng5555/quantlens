"""Dormant Gate E Stop B3a final-holdout access authority package.

This package holds the independent ``final-holdout-access-v1`` authority: its
authority-only SQLite store and the encrypted capsule/anchor registration
authority.  It is dormant local scaffolding only — nothing active imports it, no
service or socket is started, no key is generated and no environment is read.
This ``__init__`` deliberately re-exports nothing and has no side effect.
"""
