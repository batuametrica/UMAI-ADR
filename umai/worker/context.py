"""Enterprise context for the reasoning stage.

Upstream exposes threat intelligence, policy, and source-code lookups as MCP
servers that the `claude` CLI spawns as subprocesses. The servers themselves are
thin readers over YAML — the value is the data, not the transport.

Running them as tools in-process instead means no subprocess per session, no
`fastmcp` dependency, and — the reason that matters — it works against any
OpenAI-compatible endpoint. The MCP connector route needs remote servers over
URL, which a locally hosted sovereign model does not have.

Data files are read from upstream `Detection/context_providers/data/` so the
taxonomy stays in one place. Tenant-specific policy replaces `policy_store.yaml`
via the context bundle.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import yaml

DATA_ROOT = Path(__file__).resolve().parents[2] / "Detection" / "context_providers" / "data"


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except OSError:
        return {}


class ContextProviders:
    """Threat-model and policy lookups, exposed as callable tools."""

    def __init__(self, data_root: Optional[Path] = None):
        self.data_root = data_root or DATA_ROOT
        self._threats: dict[str, Any] | None = None
        self._policies: dict[str, Any] | None = None

    # -- data ----------------------------------------------------------

    @property
    def threats(self) -> dict[str, Any]:
        if self._threats is None:
            self._threats = _load_yaml(self.data_root / "threat_repository.yaml")
        return self._threats

    @property
    def policies(self) -> dict[str, Any]:
        if self._policies is None:
            self._policies = _load_yaml(self.data_root / "policy_store.yaml")
        return self._policies

    # -- tools ---------------------------------------------------------

    def get_threat_framework(self, tactic: Optional[str] = None) -> dict[str, Any]:
        """Techniques for one tactic, or the whole framework."""
        tactics = (self.threats.get("threat_framework") or {}).get("tactics") or {}
        if tactic and tactic in tactics:
            return {"tactic": tactic, **tactics[tactic]}
        return {
            "tactics": {
                name: {
                    "description": body.get("description"),
                    "techniques": [
                        {"id": t.get("id"), "name": t.get("name")}
                        for t in body.get("techniques") or []
                    ],
                }
                for name, body in tactics.items()
            }
        }

    def get_technique_details(self, technique_id: str) -> dict[str, Any]:
        """Full description and detection guidance for one ADR technique."""
        tactics = (self.threats.get("threat_framework") or {}).get("tactics") or {}
        for tactic_name, body in tactics.items():
            for technique in body.get("techniques") or []:
                if str(technique.get("id", "")).lower() == technique_id.lower():
                    return {"tactic": tactic_name, **technique}
        return {"error": f"Unknown technique: {technique_id}"}

    def search_techniques(self, keywords: list[str]) -> dict[str, Any]:
        """Techniques whose name, description, or guidance mentions the keywords."""
        needles = [k.lower() for k in keywords if k]
        tactics = (self.threats.get("threat_framework") or {}).get("tactics") or {}
        matches = []
        for tactic_name, body in tactics.items():
            for technique in body.get("techniques") or []:
                haystack = json.dumps(technique, ensure_ascii=False).lower()
                if any(needle in haystack for needle in needles):
                    matches.append(
                        {
                            "tactic": tactic_name,
                            "id": technique.get("id"),
                            "name": technique.get("name"),
                            "description": technique.get("description"),
                        }
                    )
        return {"matches": matches, "count": len(matches)}

    def get_policies(self, categories: Optional[list[str]] = None) -> dict[str, Any]:
        """Enterprise policies, optionally filtered by category."""
        policies = self.policies.get("policies") or []
        if categories:
            wanted = {c.lower() for c in categories}
            policies = [p for p in policies if str(p.get("category", "")).lower() in wanted]
        return {"policies": policies, "count": len(policies)}

    def search_policies(self, keywords: list[str]) -> dict[str, Any]:
        """Policies mentioning the keywords, for narrowing a large corpus."""
        needles = [k.lower() for k in keywords if k]
        matches = []
        for policy in self.policies.get("policies") or []:
            haystack = json.dumps(policy, ensure_ascii=False).lower()
            if any(needle in haystack for needle in needles):
                matches.append(policy)
        return {"policies": matches, "count": len(matches)}

    # -- tool wiring ---------------------------------------------------

    def tool_specs(self) -> list[dict[str, Any]]:
        """OpenAI-style tool definitions for the reasoning loop."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "get_threat_framework",
                    "description": (
                        "Get ADR threat techniques. Pass a tactic "
                        "(initial_compromise, permission_abuse, security_control_bypass, "
                        "reasoning_data_manipulation, operational_impact) to narrow it."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {"tactic": {"type": "string"}},
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_technique_details",
                    "description": (
                        "Full description and detection guidance for one technique, "
                        "e.g. ADR.T0007."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {"technique_id": {"type": "string"}},
                        "required": ["technique_id"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_techniques",
                    "description": "Find threat techniques matching keywords from the transcript.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "keywords": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["keywords"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_policies",
                    "description": (
                        "Find enterprise policies relevant to what the session did. "
                        "Each policy states how an AI request could violate it."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "keywords": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["keywords"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_policies",
                    "description": "List enterprise policies, optionally filtered by category.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "categories": {"type": "array", "items": {"type": "string"}}
                        },
                    },
                },
            },
        ]

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call from the model."""
        handlers = {
            "get_threat_framework": self.get_threat_framework,
            "get_technique_details": self.get_technique_details,
            "search_techniques": self.search_techniques,
            "get_policies": self.get_policies,
            "search_policies": self.search_policies,
        }
        handler = handlers.get(name)
        if handler is None:
            return {"error": f"Unknown tool: {name}"}
        try:
            return handler(**arguments)
        except TypeError as e:
            return {"error": f"Bad arguments for {name}: {e}"}
