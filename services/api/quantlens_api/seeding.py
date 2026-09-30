"""One workspace seeded at a time, so the first person in does not wait for the last.

Sign-in hands new-workspace seeding to a Starlette ``BackgroundTask``, which runs a sync
function in the anyio threadpool. Ten classmates signing in together therefore put ten
threads through pandas at once. The GIL serializes that work regardless, so the total is
the same either way -- but interleaved, every one of them finishes at the END of the
total. Measured on ten accounts: wall 15.2s, and the FIRST account also completed at
14.9s, for roughly 1.5s of its own work. Nobody was served early, and ten sets of frames
were resident at once on a 1GB machine shared with the web app and the backtest worker.

Running them one after another costs the same total and changes who waits: the first
workspace is ready in about a second and a half, each subsequent one lands a second and a
half later, and only the last person waits what everyone used to wait. Peak memory
becomes one account's working set instead of ten.

This is deliberately the smallest thing that achieves that. Seeding is not durable work:
a restart loses whatever is queued, exactly as the BackgroundTask it replaces did, and
the recovery is the same one the product already documents -- the Data page button, whose
endpoint is idempotent per bundled series. Making it durable would mean putting it in the
run queue, which lives in the worker process and would drag the sealed worker image into
a change it has no business being in.
"""

from __future__ import annotations

import logging
import queue
import threading
from pathlib import Path

from . import market_bundle

logger = logging.getLogger(__name__)

# Unbounded on purpose: the ceiling is MAX_ACCOUNTS, and dropping a request would leave
# somebody with an empty workspace and no signal that it happened.
_QUEUE: queue.Queue[tuple[Path, str]] = queue.Queue()
_WORKER: threading.Thread | None = None
_WORKER_LOCK = threading.Lock()

# Pending covers queued AND in-flight, so a caller waiting for quiet cannot observe the
# gap between a job being taken off the queue and being finished.
_PENDING = 0
_IDLE = threading.Condition()


def _ensure_worker() -> None:
    global _WORKER
    with _WORKER_LOCK:
        if _WORKER is None or not _WORKER.is_alive():
            _WORKER = threading.Thread(
                target=_serve, name="quantlens-workspace-seed", daemon=True)
            _WORKER.start()


def _serve() -> None:
    while True:
        var_dir, account_id = _QUEUE.get()
        try:
            market_bundle.seed_new_workspace(var_dir, account_id=account_id)
        except Exception:  # noqa: BLE001 - one bad workspace must not stop the queue
            logger.warning("workspace seeding failed account=%s", account_id,
                           exc_info=True)
        finally:
            _QUEUE.task_done()
            with _IDLE:
                global _PENDING
                _PENDING -= 1
                _IDLE.notify_all()


def submit(var_dir: Path, *, account_id: str) -> None:
    """Queue one workspace for seeding and return immediately.

    Called from the sign-in response's background task, so it must never do the work
    itself and must never raise into a sign-in.
    """
    global _PENDING
    try:
        _ensure_worker()
        with _IDLE:
            _PENDING += 1
        _QUEUE.put((Path(var_dir), account_id))
        depth = _QUEUE.qsize()
        if depth > 1:
            logger.info("workspace seeding queued behind %d other(s)", depth - 1)
    except Exception:  # noqa: BLE001 - an empty workspace beats a failed sign-in
        logger.warning("could not queue workspace seeding account=%s", account_id,
                       exc_info=True)


def wait_until_idle(timeout: float = 120.0) -> bool:
    """Block until nothing is queued or in flight. For tests and shutdown checks."""
    with _IDLE:
        return _IDLE.wait_for(lambda: _PENDING == 0, timeout=timeout)


def pending() -> int:
    """How many workspaces are queued or being seeded right now."""
    with _IDLE:
        return _PENDING
