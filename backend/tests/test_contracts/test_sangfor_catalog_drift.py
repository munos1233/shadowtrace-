"""Sangfor XDR catalog + capability matrix gates (alignment plan Layer 0)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO_ROOT / "scripts"
_HTML = _REPO_ROOT / "挑战杯物料" / "OpenAPIDocument" / "深信服XDR平台接口开放列表.html"
_CATALOG = _REPO_ROOT / "contracts" / "vendor" / "sangfor_xdr" / "catalog.json"
_MATRIX = _REPO_ROOT / "contracts" / "vendor" / "sangfor_xdr" / "capability_matrix.yaml"

if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from extract_sangfor_catalog import (  # noqa: E402
    METHOD_BY_REQUEST_TYPE,
    catalog_to_json,
    load_catalog_from_html,
    parse_project_json,
)

EXPECTED_OPERATION_COUNT = 129
EXPECTED_POST_COUNT = 94

P0_PATHS = (
    ("POST", "/api/xdr/v1/incidents/list"),
    ("POST", "/api/xdr/v1/incidents/dealstatus"),
    ("POST", "/api/xdr/v1/incidents/dealstatus/list"),
)


def _load_check_module():
    spec = importlib.util.spec_from_file_location(
        "check_sangfor_catalog_drift",
        _SCRIPTS / "check_sangfor_catalog_drift.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _require_source_html() -> None:
    """The vendor export is private challenge material, not a CI artifact."""
    if not _HTML.is_file():
        pytest.skip("private Sangfor OpenAPI HTML is not present in this checkout")


def _committed_catalog() -> dict[str, Any]:
    return json.loads(_CATALOG.read_text(encoding="utf-8"))


def _matrix_rows() -> list[dict[str, Any]]:
    payload = yaml.safe_load(_MATRIX.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    rows = payload.get("operations")
    assert isinstance(rows, list)
    return [row for row in rows if isinstance(row, dict)]


def _find_op(catalog: dict[str, Any], method: str, path: str) -> dict[str, Any]:
    matches = [
        op for op in catalog["operations"] if op.get("method") == method and op.get("path") == path
    ]
    assert matches, f"missing catalog op {method} {path}"
    assert len(matches) == 1, f"duplicate catalog op {method} {path}"
    return matches[0]


def _iter_param_nodes(
    nodes: list[dict[str, Any]] | None, prefix: str = ""
) -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    for node in nodes or []:
        key = str(node.get("paramKey") or "")
        path = f"{prefix}.{key}" if prefix else key
        found.append((path, node))
        found.extend(_iter_param_nodes(node.get("childList") or [], path))
    return found


def _response_nodes(op: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    nodes: list[tuple[str, dict[str, Any]]] = []
    for response in op.get("response") or []:
        nodes.extend(_iter_param_nodes(response.get("paramList") or []))
    return nodes


def test_html_post_count_is_94() -> None:
    _require_source_html()
    html = _HTML.read_text(encoding="utf-8")
    project = parse_project_json(html)
    posts = 0
    total = 0
    for group in project.get("apiGroupList") or []:
        for api in group.get("apiList") or []:
            total += 1
            request_type = (api.get("baseInfo") or {}).get("apiRequestType")
            if METHOD_BY_REQUEST_TYPE.get(request_type) == "POST":
                posts += 1
    assert total == EXPECTED_OPERATION_COUNT
    assert posts == EXPECTED_POST_COUNT


def test_committed_catalog_matches_fresh_html_extract() -> None:
    _require_source_html()
    fresh = load_catalog_from_html(_HTML)
    committed = _committed_catalog()
    assert catalog_to_json(fresh) == catalog_to_json(committed)
    assert committed["operation_count"] == EXPECTED_OPERATION_COUNT
    assert len(committed["operations"]) == EXPECTED_OPERATION_COUNT
    assert sum(1 for op in committed["operations"] if op["method"] == "POST") == (
        EXPECTED_POST_COUNT
    )


def test_check_sangfor_catalog_drift_passes() -> None:
    _require_source_html()
    mod = _load_check_module()
    assert mod.main() == 0


def test_catalog_includes_v2_vpc_and_no_mock_uri() -> None:
    catalog = _committed_catalog()
    _find_op(catalog, "POST", "/api/xdr/v2/assets/vpc")
    for op in catalog["operations"]:
        assert "/mock-xdr/" not in str(op.get("path") or "")


def test_p0_matrix_paths_match_plan() -> None:
    rows = _matrix_rows()
    p0 = {(row["method"], row["path"]) for row in rows if row.get("in_loop") == "p0"}
    assert p0 == set(P0_PATHS)


def test_incidents_list_response_has_item_uuid() -> None:
    op = _find_op(_committed_catalog(), "POST", "/api/xdr/v1/incidents/list")
    keys = {path for path, _node in _response_nodes(op)}
    assert "data.item.uuId" in keys


def test_dealstatus_list_enum_is_one_through_six() -> None:
    op = _find_op(_committed_catalog(), "POST", "/api/xdr/v1/incidents/dealstatus/list")
    request_keys = {path for path, _node in _iter_param_nodes(op.get("request") or [])}
    assert "ids" in request_keys
    assert "uuIds" not in request_keys
    nodes = [node for path, node in _response_nodes(op) if path == "data.item.dealStatus"]
    assert nodes, "dealStatus missing from dealstatus/list response"
    node = nodes[0]
    values = [item.get("value") for item in node.get("paramValueList") or []]
    assert values == [1, 2, 3, 4, 5, 6]
    assert "1 待处置" in str(node.get("paramName") or "")
    assert "6 已遏制" in str(node.get("paramName") or "")


def test_alerts_list_uses_alert_deal_status() -> None:
    op = _find_op(_committed_catalog(), "POST", "/api/xdr/v1/alerts/list")
    request_keys = {path for path, _node in _iter_param_nodes(op.get("request") or [])}
    response_keys = {path for path, _node in _response_nodes(op)}
    assert "alertDealStatus" in request_keys
    assert "data.item.alertDealStatus" in response_keys
    assert "data.item.dealStatus" not in response_keys


def test_analysislog_list_has_no_total_and_count_has_total() -> None:
    catalog = _committed_catalog()
    list_op = _find_op(catalog, "POST", "/api/xdr/v1/analysislog/networksecurity/list")
    count_op = _find_op(catalog, "POST", "/api/xdr/v1/analysislog/networksecurity/count")
    list_data_keys = {
        path
        for path, _node in _response_nodes(list_op)
        if path == "data" or path.startswith("data.")
    }
    assert "data.item" in list_data_keys
    assert "data.page" in list_data_keys
    assert "data.pageSize" in list_data_keys
    assert "data.total" not in list_data_keys
    count_keys = {path for path, _node in _response_nodes(count_op)}
    assert "data.total" in count_keys


def test_virusscantask_task_id_placeholder_when_restful_empty() -> None:
    op = _find_op(
        _committed_catalog(),
        "GET",
        "/api/xdr/v1/responses/virusscantask/:taskId",
    )
    assert op["path_placeholders"] == [":taskId"]
    assert op["restful_params"] == []


def test_blockdevice_list_response_has_device_id() -> None:
    op = _find_op(_committed_catalog(), "POST", "/api/xdr/v1/device/blockdevice/list")
    keys = {path for path, _node in _response_nodes(op)}
    assert "data.item.deviceId" in keys


def test_matrix_covers_every_catalog_operation() -> None:
    catalog = _committed_catalog()
    rows = _matrix_rows()
    matrix_pairs = {(row["method"], row["path"]) for row in rows if row.get("path")}
    catalog_pairs = {(op["method"], op["path"]) for op in catalog["operations"]}
    missing = catalog_pairs - matrix_pairs
    extra_vendor = matrix_pairs - catalog_pairs
    assert not missing, f"catalog ops missing from matrix: {sorted(missing)[:10]}"
    assert not extra_vendor, f"matrix paths not in catalog: {sorted(extra_vendor)[:10]}"


def test_isolate_create_is_unsupported_write_without_invented_path() -> None:
    rows = _matrix_rows()
    isolate = [row for row in rows if row.get("internal_name") == "isolate_host_create"]
    assert len(isolate) == 1
    row = isolate[0]
    assert row["role"] == "unsupported_write"
    assert row["path"] is None
    assert row["method"] is None
    for row in rows:
        path = str(row.get("path") or "")
        name = str(row.get("internal_name") or "")
        if "isolate" in path and row.get("role") == "write":
            pytest.fail(f"invented isolate write path: {row}")
        if name.startswith("isolate") and row.get("role") == "write":
            pytest.fail(f"isolate write row must not exist: {row}")


def test_block_domain_only_uses_network_path() -> None:
    rows = _matrix_rows()
    domain = [row for row in rows if row.get("internal_name") == "block_domain_network"]
    assert len(domain) == 1
    assert domain[0]["path"] == "/api/xdr/v1/responses/blockiprule/network"
    assert domain[0]["role"] == "write"
    for row in rows:
        if row.get("internal_name") == "block_domain_network":
            assert "endpoint" not in str(row.get("path") or "")
        if row.get("internal_name") == "block_ip_endpoint":
            assert row["path"] == "/api/xdr/v1/responses/blockiprule/endpoint"


def test_unsupported_write_kernel_tools_have_no_vendor_path() -> None:
    names = {
        "isolate_host_create",
        "disable_account",
        "force_logout",
        "reset_password",
        "revoke_token",
        "block_process",
        "quarantine_file_create",
    }
    rows = {row["internal_name"]: row for row in _matrix_rows()}
    for name in names:
        row = rows[name]
        assert row["role"] == "unsupported_write"
        assert row["path"] is None
        assert row["method"] is None
        assert row["disposition_intent"] == "ENTITY_ACTION_SUBMIT"
