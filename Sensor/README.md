# ADR Sensor

**Agentic Detection & Response (ADR) Sensor** - Security observability for AI coding agents.

ADR Sensor is a Python library that collects telemetry from AI coding agents to enable security monitoring, threat detection, and observability. It parses logs from multiple AI agent platforms and normalizes them into a unified schema for downstream analysis.

> **Paper:** [ADR: An Agentic Detection System for Enterprise Agentic AI Security](https://arxiv.org/abs/2605.17380)  
> **Code:** [github.com/uber/ADR](https://github.com/uber/ADR)

## Supported AI Agents


| Agent                         | Log Format                    | Platform     |
| ----------------------------- | ----------------------------- | ------------ |
| **Claude Code**               | JSONL (`~/.claude/projects/`) | Windows, macOS, Linux |
| **Cursor IDE**                | SQLite (`state.vscdb`)        | Windows, macOS, Linux |
| **Cline (Claude Dev)**        | JSON task files               | Windows, macOS, Linux |
| **Claude Desktop Agent Mode** | JSONL audit logs / sidecars   | Windows, macOS |
| **OpenAI Codex CLI**          | JSONL (`$CODEX_HOME/sessions`, else `~/.codex/sessions/`) | Windows, macOS, Linux |
| **Warp Terminal**             | SQLite (`warp.sqlite`)        | macOS (Windows deferred) |

UMAI: Cursor and Cline resolve from the VS Code-family user-data root —
`%APPDATA%` on Windows, `~/Library/Application Support` on macOS, `~/.config`
on Linux — via `adr_sensor/platform_paths.py`. Cline is scanned in every host
it can be installed in: Cursor, VS Code, VS Code Insiders, VSCodium and
Windsurf.


## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     AI Agent Logs                       │
│  Claude Code │ Cursor │ Cline │ Codex │ Warp │ Desktop  │
└──────┬───────┴───┬────┴───┬───┴───┬───┴──┬───┴────┬─────┘
       │           │        │       │      │        │
       ▼           ▼        ▼       ▼      ▼        ▼
┌─────────────────────────────────────────────────────────┐
│              Source-Specific Parsers                    │
│         (Each implements BaseParser)                    │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│            Unified Schema (AgentEvent)                  │
│   session_id │ timestamp │ chat_history │ tools │ model │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│              AgentObserver (Orchestrator)               │
│       Ingest → Filter → Display → Export                │
└─────────────────────┬───────────────────────────────────┘
                      │
              ┌───────┴───────┐
              ▼               ▼
        JSON/JSONL      Your Detection
         Export          Pipeline / SIEM
```

## Quick Start

### Installation

Tagged releases are installed from [PyPI](https://pypi.org/project/adr-sensor/):

```bash
pip install adr-sensor
```

Or install from source:

```bash
git clone https://github.com/uber/ADR
cd ADR/Sensor
pip install .
```

### CLI Usage

```bash
# Ingest from all supported agents
adr-sensor

# Ingest from a specific source
adr-sensor --source claude
adr-sensor --source cursor
adr-sensor --source codex

# Save individual session files (incremental)
adr-sensor --save-sessions

# Export as JSONL
adr-sensor --output-format jsonl

# Include all history (not just last 2 weeks)
adr-sensor --all-history

# Custom output directory
adr-sensor --output-dir ./my-output
```

### Python API

```python
from adr_sensor import AgentObserver

# Create observer
observer = AgentObserver()

# Ingest from all sources
events, configs = observer.ingest_all()

# Or from a specific source
events, configs = observer.ingest_all(source_filter="claude")

# Display summary
observer.display_summary(events, configs)

# Save to file
observer.save_to_file(events, configs, output_format="json")

# Analyze events
for event in events:
    print(f"Source: {event.source}, Session: {event.session_id}")
    print(f"Messages: {len(event.chat_history)}")

    for msg in event.chat_history:
        if msg.tools:
            for tool in msg.tools:
                print(f"  Tool: {tool.tool_name} ({tool.tool_type})")
                print(f"  Args: {tool.arguments}")
```

## Output Schema

### AgentEvent

Each parsed session produces an `AgentEvent` with the following structure:

```json
{
  "uuid": "sha256-hash",
  "timestamp": "2025-06-15T10:30:00+00:00",
  "source": "claude",
  "session_id": "claude_abc123",
  "hostname": "my-laptop",
  "username": "developer",
  "model": "claude-sonnet-4-20250514",
  "project_path": "/home/user/my-project",
  "chat_history": [
    {
      "role": "user",
      "content": "Help me fix this bug",
      "tools": [],
      "sequence_id": "msg_0"
    },
    {
      "role": "assistant",
      "content": "Let me look at the code.",
      "tools": [
        {
          "tool_name": "read_file",
          "tool_type": "tool_use",
          "arguments": {"path": "main.py"},
          "result": "def hello(): ...",
          "status": "success"
        }
      ],
      "sequence_id": "msg_1"
    }
  ]
}
```

## Adding a New Parser

ADR Sensor is designed to be extensible. To add support for a new AI agent:

1. Create a new parser in `adr_sensor/parsers/`:

```python
from adr_sensor.parsers.base_parser import BaseParser
from adr_sensor.schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage

class MyAgentParser(BaseParser):
    def __init__(self):
        self.base_path = Path.home() / ".my-agent/logs"

    def parse_all(self) -> list[AgentEvent]:
        entries = []
        # Parse your agent's log files
        # Convert to AgentEvent objects
        return entries
```

1. Register it in `adr_sensor/observer.py`:

```python
from .parsers.my_agent_parser import MyAgentParser

class AgentObserver:
    def __init__(self, ...):
        ...
        self.my_agent_parser = MyAgentParser()

    def ingest_all(self, source_filter="all"):
        ...
        if source_filter in ["all", "my_agent"]:
            entries = self.my_agent_parser.parse_all()
            all_entries.extend(entries)
```

1. Add tests in `tests/`.

## Security Use Cases

ADR Sensor enables detection of:

- **Suspicious tool usage** - Unusual MCP tools, unauthorized file access, credential exfiltration
- **Prompt injection** - Malicious content injected into agent conversations
- **Supply chain risks** - Malicious MCP server configurations, suspicious packages
- **Data exfiltration** - Sensitive data accessed or transmitted by agents
- **Anomalous behavior** - Activity outside normal patterns, burst tool usage

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --cov=adr_sensor

# Lint
ruff check adr_sensor/
ruff format adr_sensor/
```

## Project Structure

```
adr-sensor/
├── adr_sensor/
│   ├── __init__.py          # Package exports
│   ├── cli.py               # CLI entry point
│   ├── observer.py          # AgentObserver orchestrator
│   ├── parsers/
│   │   ├── base_parser.py   # Abstract base class
│   │   ├── claude_parser.py
│   │   ├── cursor_parser.py
│   │   ├── cline_parser.py
│   │   ├── claude_desktop_parser.py
│   │   ├── codex_parser.py
│   │   └── warp_parser.py
│   ├── schemas/
│   │   ├── agent_event_schema.py    # AgentEvent, ChatMessage, ToolUsage
│   │   └── system_config_schema.py  # SystemConfiguration
│   └── utils/
│       ├── string_utils.py
│       └── timestamp_utils.py
├── tests/
├── examples/
├── CONTRIBUTING.md
├── LICENSE
├── pyproject.toml
└── README.md
```

## License

Apache License 2.0. See the [Sensor license](https://github.com/uber/ADR/blob/main/Sensor/LICENSE) for details.

## Contributing

We welcome contributions! See the [Sensor contribution guide](https://github.com/uber/ADR/blob/main/Sensor/CONTRIBUTING.md) for guidelines.

Maintainers can publish tagged releases by following the [release guide](https://github.com/uber/ADR/blob/main/docs/RELEASING.md).

Especially welcome:

- New parsers for additional AI agents
- Detection rules and analysis patterns
- Documentation improvements
- Bug reports and fixes
