"""A published image must describe the same code and tools that CI tested."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import mcp_server  # noqa: E402


def test_versions_and_tools_are_in_sync():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    mcp = json.loads((ROOT / "mcp.json").read_text())
    server = json.loads((ROOT / "server.json").read_text())

    versions = {
        project["project"]["version"],
        mcp["version"],
        server["version"],
        mcp_server.SERVER_VERSION,
    }
    assert versions == {"0.2.1"}

    implemented = set(mcp_server.HANDLERS)
    advertised = set(mcp["tools"])
    assert implemented == advertised
    assert server["packages"][0]["identifier"].endswith(":v0.2.1")
    assert "version" not in server["packages"][0]

    setuptools = project["tool"]["setuptools"]
    assert setuptools["packages"] == ["lucent"]
    assert set(setuptools["py-modules"]) == {"audit", "common", "comprehend", "danger"}


def test_release_workflow_is_version_bound_and_supply_chain_pinned():
    workflow = (ROOT / ".github" / "workflows" / "publish-mcp.yml").read_text()
    assert "workflow_dispatch" not in workflow
    assert "releases/latest" not in workflow
    assert "sha256sum --check --strict" in workflow
    assert "MCP_PUBLISHER_VERSION: v1.7.9" in workflow
    assert re.search(r"MCP_PUBLISHER_LINUX_AMD64_SHA256: [0-9a-f]{64}", workflow)
    assert "ghcr.io/beepboop2025/lucent-api:v0.2.1" in workflow
    assert 'test "$RELEASE_TAG" = "v$VERSION"' in workflow
    assert "python -m ruff check lucent" in workflow
    assert "python -m pip wheel . --no-deps" in workflow
    assert "scripts/review.py --no-lint --no-semverify --report-only" in workflow
    assert "LUCENT_ACCESS_MODE=open" in workflow
    assert "127.0.0.1:8780/ready" in workflow

    ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "LUCENT_ACCESS_MODE=open" in ci_workflow
    assert "127.0.0.1:8780/ready" in ci_workflow


def test_docker_context_excludes_local_bytecode():
    dockerignore = (ROOT / ".dockerignore").read_text()
    assert "**/__pycache__/" in dockerignore
    assert "**/*.py[co]" in dockerignore


def test_hosted_image_contains_the_official_x402_runtime_and_safe_defaults():
    api_requirements = (ROOT / "requirements-api.txt").read_text()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dockerfile = (ROOT / "Dockerfile.api").read_text()
    assert "x402>=2.18,<3" in api_requirements
    assert "jsonschema>=4.23,<5" in api_requirements
    assert "x402>=2.18,<3" in project["project"]["dependencies"]
    assert "jsonschema>=4.23,<5" in project["project"]["dependencies"]
    assert "LUCENT_ACCESS_MODE=disabled" in dockerfile
    assert "LUCENT_VERIFIED_SOURCE_MODE=off" in dockerfile
    assert "LUCENT_X402_ENABLED=false" in dockerfile
    assert "127.0.0.1:8780/ready" in dockerfile


def test_mcp_registry_manifest_uses_the_current_schema():
    server = json.loads((ROOT / "server.json").read_text())
    assert server["$schema"].endswith("/2025-12-11/server.schema.json")


def test_railway_deploys_the_hardened_api_image_with_readiness_gating():
    railway = json.loads((ROOT / "railway.json").read_text())
    assert railway["build"] == {
        "builder": "DOCKERFILE",
        "dockerfilePath": "Dockerfile.api",
    }
    assert railway["deploy"]["healthcheckPath"] == "/ready"
    assert railway["deploy"]["restartPolicyType"] == "ON_FAILURE"
    assert railway["deploy"]["drainingSeconds"] == 10
