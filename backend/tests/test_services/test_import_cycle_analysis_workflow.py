"""Import-graph smoke tests for analysis_only_pipeline ↔ workflow_graph (ISSUE-970)."""

from __future__ import annotations


def test_analysis_only_pipeline_imports_without_cycle() -> None:
    """Bare import must succeed without pre-loading workflow_graph."""
    import app.services.analysis_only_pipeline as pipeline

    assert pipeline.AnalysisOnlyPipeline is not None
    assert pipeline.run_rag_stage is not None


def test_workflow_graph_imports_without_cycle() -> None:
    """workflow_graph must import independently of analysis_only_pipeline."""
    import app.orchestration.workflow_graph as workflow_graph

    assert workflow_graph.rag_node is not None
    assert workflow_graph.planner_node is not None


def test_orchestration_package_imports_without_cycle() -> None:
    """orchestration.__init__ eagerly exports graph nodes; must not cycle."""
    import app.orchestration as orchestration

    assert orchestration.rag_node is not None
    assert orchestration.planner_node is not None
