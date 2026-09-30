"""AT-7.4 — a known split held across its date leaves position value continuous within
tolerance (no phantom return). AT-7.2 — missing bars follow the declared policy: small
gaps are listed; gaps beyond threshold fail loudly as data_quality_failed."""

import json

import pandas as pd
import pytest

from quantlens_worker.engine import backtest
from quantlens_worker.snapshot import (
    DataQualityError,
    canonical_snapshot_identity,
    load_frame,
    verify_snapshot_integrity,
)
from tests.conftest import bday_frame, make_snapshot_dir

COSTS = {"commission_bps": 1, "slippage_bps": 5}
RULE = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 3}


def _split_fixture(tmp_path):
    # Raw tape: steady riser 100 -> ~130; 2:1 split at bar 10 halves the RAW price.
    n = 20
    raw_close, raw_open = [], []
    for i in range(n):
        underlying = 100.0 + 1.5 * i
        factor = 0.5 if i >= 10 else 1.0
        raw_close.append(round(underlying * factor, 4))
        raw_open.append(round((underlying - 0.5) * factor, 4))
    df = bday_frame("2024-01-01", raw_close, raw_open)
    split_date = df["date"].iloc[10]
    return make_snapshot_dir(tmp_path / "snap", {"SPL": df},
                             splits={"SPL": [{"date": split_date, "ratio": 2.0}]}), df


def test_split_held_across_date_no_phantom_return(tmp_path):
    snap_dir, raw = _split_fixture(tmp_path)
    adj, _gaps = load_frame("SPL", raw["date"].iloc[0], raw["date"].iloc[-1], snap_dir)

    # Raw tape has a ~-50% jump at the split; the adjusted tape must not.
    raw_rets = pd.Series(raw["close"]).pct_change().abs()
    adj_rets = adj["close"].pct_change().abs()
    assert raw_rets.max() > 0.4
    assert adj_rets.max() < 0.05, "back-adjustment must remove the split discontinuity"

    # Held position across the split: no phantom equity move on the split date.
    result = backtest(adj, RULE, COSTS)
    eq = result["equity"]
    assert (eq["position"].iloc[8:14] == 1).all(), "must be long across the split date"
    split_day_ret = eq["equity"].pct_change().abs().iloc[10]
    assert split_day_ret < 0.05, f"phantom return across split: {split_day_ret:.2%}"


def test_small_gap_listed_and_run_continues(tmp_path):
    df = bday_frame("2024-01-01", [float(100 + i) for i in range(30)])
    df = df.drop(index=[7, 8]).reset_index(drop=True)  # 2-day gap, within policy
    snap = make_snapshot_dir(tmp_path / "snap", {"GAP": df})
    frame, gap_report = load_frame("GAP", df["date"].iloc[0], df["date"].iloc[-1], snap)
    assert gap_report["missing_day_count"] == 2
    assert gap_report["max_consecutive"] == 2
    assert gap_report["gaps"][0]["days"] == 2
    assert len(frame) == 28


def test_gap_beyond_threshold_fails_data_quality(tmp_path):
    df = bday_frame("2024-01-01", [float(100 + i) for i in range(30)])
    df = df.drop(index=[7, 8, 9, 10, 11]).reset_index(drop=True)  # 5-day gap
    snap = make_snapshot_dir(tmp_path / "snap", {"GAP": df})
    with pytest.raises(DataQualityError) as exc:
        load_frame("GAP", df["date"].iloc[0], df["date"].iloc[-1], snap)
    assert exc.value.code == "GAP_BEYOND_THRESHOLD"


def test_range_outside_coverage_fails_loudly(tmp_path):
    df = bday_frame("2024-01-01", [float(100 + i) for i in range(30)])
    snap = make_snapshot_dir(tmp_path / "snap", {"COV": df})
    with pytest.raises(DataQualityError) as exc:
        load_frame("COV", "2020-01-01", df["date"].iloc[-1], snap)
    assert exc.value.code == "RANGE_OUTSIDE_COVERAGE"


def test_tampered_snapshot_detected(tmp_path):
    df = bday_frame("2024-01-01", [float(100 + i) for i in range(30)])
    snap = make_snapshot_dir(tmp_path / "snap", {"TMP": df})
    (snap / "TMP.csv").write_text("date,open,high,low,close,volume\n")
    with pytest.raises(DataQualityError) as exc:
        verify_snapshot_integrity(snap)
    assert exc.value.code == "SNAPSHOT_TAMPERED"


@pytest.mark.parametrize("field", ["coverage", "splits", "execution"])
def test_canonical_snapshot_identity_binds_material_metadata(tmp_path, field):
    df = bday_frame("2024-01-01", [float(100 + i) for i in range(30)])
    snap = make_snapshot_dir(tmp_path / "snap", {"BND": df})
    path = snap / "snapshot.json"
    meta = json.loads(path.read_text())
    if field == "coverage":
        meta["coverage"]["BND"]["end"] = "2099-12-31"
    elif field == "splits":
        meta["splits"]["BND"] = [{"date": df["date"].iloc[10], "ratio": 2.0}]
    else:
        meta["execution"]["fill_price"] = "same_session_close"
    # Leave the top-level digest/id untouched: any material metadata edit must break it.
    path.write_text(json.dumps(meta, indent=2, sort_keys=True))
    with pytest.raises(DataQualityError) as exc:
        verify_snapshot_integrity(snap)
    assert exc.value.code == "SNAPSHOT_IDENTITY_MISMATCH"


def test_rehashed_but_unsupported_execution_semantics_are_rejected(tmp_path):
    df = bday_frame("2024-01-01", [float(100 + i) for i in range(30)])
    snap = make_snapshot_dir(tmp_path / "snap", {"EXE": df})
    path = snap / "snapshot.json"
    meta = json.loads(path.read_text())
    meta["execution"]["fill_price"] = "same_session_close"
    meta["sha256"], meta["snapshot_id"] = canonical_snapshot_identity(meta)
    path.write_text(json.dumps(meta, indent=2, sort_keys=True))
    with pytest.raises(DataQualityError) as exc:
        verify_snapshot_integrity(snap)
    assert exc.value.code == "SNAPSHOT_EXECUTION_UNSUPPORTED"


def test_requested_boundary_missing_bar_is_not_silently_trimmed(tmp_path):
    complete = bday_frame("2024-01-01", [float(100 + i) for i in range(40)])
    requested_start = complete["date"].iloc[10]
    requested_end = complete["date"].iloc[25]
    missing_boundary = complete.drop(index=10).reset_index(drop=True)
    snap = make_snapshot_dir(tmp_path / "snap", {"BDY": missing_boundary})
    _frame, gaps = load_frame("BDY", requested_start, requested_end, snap)
    assert gaps["requested_range"] == {"start": requested_start, "end": requested_end}
    assert gaps["missing_day_count"] == 1
    assert gaps["gaps"][0] == {"start": requested_start, "days": 1}
    assert gaps["returned_range"]["start"] > requested_start


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda df: df.assign(high=df["low"] - 1.0), "OHLC_INVALID"),
        (lambda df: df.assign(open=float("inf")), "OHLC_INVALID"),
        (lambda df: df.assign(low=-1.0), "OHLC_INVALID"),
        (lambda df: df.assign(
            date=df["date"].mask(df.index == 5, "2024-01-06")), "DATES_INVALID"),
        (lambda df: pd.concat([df.iloc[:8], df.iloc[[7]], df.iloc[8:]], ignore_index=True),
         "DATES_DUPLICATE"),
        (lambda df: pd.concat(
            [df.iloc[:7], df.iloc[[8]], df.iloc[[7]], df.iloc[9:]], ignore_index=True),
         "DATES_UNORDERED"),
    ],
)
def test_invalid_ohlc_or_dates_fail_loudly(tmp_path, mutate, code):
    valid = bday_frame("2024-01-01", [float(100 + i) for i in range(30)])
    broken = mutate(valid.copy(deep=True))
    snap = make_snapshot_dir(tmp_path / "snap", {"BAD": broken})
    with pytest.raises(DataQualityError) as exc:
        load_frame("BAD", broken["date"].iloc[0], broken["date"].iloc[-1], snap)
    assert exc.value.code == code
