from __future__ import annotations

from core.feedback_loop import run_feedback_loop


class _Target:
    name = "t"


def _gen_fn(target, feedback, seeds, generation):
    return f"suite-{generation}"


def test_stops_on_success(tmp_path):
    scenarios = [
        [{"confirmed": False, "http_status": 200, "evidence": "ok"}],
        [{"confirmed": True, "http_status": 200, "evidence": "matcher hit"}],
    ]
    state = {"i": 0}

    def fire(suite, target):
        i = state["i"]; state["i"] += 1
        return scenarios[min(i, len(scenarios) - 1)]

    res = run_feedback_loop(_Target(), _gen_fn, fire, max_generations=5, results_dir=tmp_path)
    assert res.status == "success"
    assert res.total_generations == 2
    assert res.generations[-1].exploited is True


def test_stops_on_no_progress(tmp_path):
    def fire(suite, target):
        return [{"confirmed": False, "http_status": 200, "evidence": "ok"}]

    res = run_feedback_loop(_Target(), _gen_fn, fire, max_generations=10, max_no_progress=3, results_dir=tmp_path)
    assert res.status == "no_progress"
    assert res.total_generations == 3


def test_budget_exhausted_when_signal_but_no_success(tmp_path):
    def fire(suite, target):
        return [{"confirmed": False, "http_status": 500, "evidence": ""}]

    res = run_feedback_loop(_Target(), _gen_fn, fire, max_generations=3, max_no_progress=3, results_dir=tmp_path)
    assert res.status == "budget_exhausted"
    assert res.total_generations == 3


def test_writes_log_files(tmp_path):
    def fire(suite, target):
        return [{"confirmed": True, "evidence": "hit"}]

    run_feedback_loop(_Target(), _gen_fn, fire, max_generations=2, results_dir=tmp_path)
    assert (tmp_path / "feedback_runs.csv").is_file()
    assert (tmp_path / "feedback_findings.ndjson").is_file()
