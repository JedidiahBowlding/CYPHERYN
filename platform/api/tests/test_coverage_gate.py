import runpy
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "check_critical_coverage.py"


def windows_source_path(suffix: str) -> str:
    return "src\\intel_platform\\" + suffix.replace("/", "\\")


def test_critical_coverage_gate_normalizes_windows_report_paths() -> None:
    module = runpy.run_path(str(SCRIPT), run_name="coverage_gate_test")
    thresholds = module["THRESHOLDS"]
    report = {
        "files": {
            windows_source_path(suffix): {"summary": {"percent_covered": 100}}
            for suffix in thresholds
        }
    }

    assert module["check"](report) == []
