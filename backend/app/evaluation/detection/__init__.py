"""Detection offline/shadow evaluation package (ISSUE-126 / #631)."""

from app.evaluation.detection.production_runner import (
    DetectionProductionComparisonRunner,
    DetectionProductionComparisonRunRequest,
    run_production_comparison,
)
from app.evaluation.detection.runner import (
    DetectionEvaluationRunner,
    DetectionEvaluationRunRequest,
    run_fixture_detection_evaluation,
)

__all__ = [
    "DetectionEvaluationRunRequest",
    "DetectionEvaluationRunner",
    "DetectionProductionComparisonRunRequest",
    "DetectionProductionComparisonRunner",
    "run_fixture_detection_evaluation",
    "run_production_comparison",
]
