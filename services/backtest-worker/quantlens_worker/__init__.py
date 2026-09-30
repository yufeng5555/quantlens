"""QuantLens Gate 2 deterministic worker package.

Numerical thread limits are fixed before importing pandas/numpy-backed submodules. This
does not turn the local prototype into a reproducible container, but it removes a major
source of same-machine BLAS nondeterminism and is bound into the manifest's local runtime
digest.
"""

from __future__ import annotations

import os

for _name in (
    "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS", "NUMEXPR_NUM_THREADS",
):
    os.environ[_name] = "1"
