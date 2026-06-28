# DATN-Packetra

## Overview

Packetra is a Python and PySide6 network traffic analysis application. It is designed to help users inspect packet data, group related traffic into flows, export flow data to CSV, run AI-based flow classification, and visualize results through dashboards and topology views.

The application supports:

- local live capture on Windows
- opening `.pcap` and `.pcapng` files
- named pipe ingestion on Windows
- remote capture over SSH on Linux
- remote capture through a Windows agent
- packet inspection, filtering, search, and stream following
- flow aggregation and feature extraction
- AI inference on flows
- dashboard and topology visualization
- packet comments and PCAPNG metadata handling

## What the application does

Packetra follows a simple pipeline:

```text
capture source
-> decode packets
-> show packet list, details, and bytes
-> filter, search, and inspect
-> group packets into flows
-> export flow data to CSV
-> run AI inference
-> show summaries in dashboards and topology views
```

In practice, the user can choose a local interface, a remote interface, a named pipe, a capture file, or a demo file. The application then parses packets into an internal `PacketRecord` model and keeps enough state to support conversations, statistics, follow-stream views, and higher-level analysis.

## Main features

### Capture

- live capture through Npcap on Windows
- capture from `.pcap` and `.pcapng` files
- remote capture over SSH using `tcpdump`
- remote capture on Windows using `PacketraAgent`
- named pipe capture on Windows
- demo capture files from `demo/`
- capture filter presets and validation
- auto-save and rollover support

### Packet analysis

- packet list, packet details tree, and hex view
- protocol, time, length, port, and info display
- packet comments and capture comments
- conversation tracking
- protocol statistics
- capture information and expert information
- stream following and packet highlighting

### Filtering and search

- custom display filter engine in `core/filtering.py`
- logical operators such as `and`, `or`, and `not`
- comparison operators and `contains`
- protocol aliases and hierarchical field resolution
- packet search with next, previous, first, and last navigation

### Flow and CSV export

- flow grouping for bidirectional communication
- flow keys and flow state tracking
- CIC-style compatibility mode
- CSV export from packets or capture files
- internal CSV schemas and CIC-compatible schemas

### AI analysis

- flow feature extraction
- model loading and preprocessing
- TorchScript inference
- label and confidence output
- rule-based behavior summaries

### Dashboard

- dashboard templates and user dashboards
- drag-and-drop dashboard editor
- query engine with filter, group, metric, sort, and limit support
- advanced helpers such as pivot, top N, bottom N, and outlier checks
- multiple chart types and topology widgets

### Topology

- network graph visualization using `QGraphicsView` and `QGraphicsScene`
- endpoint and conversation visualization
- zoom, pan, and selection support

## Repository layout

| Path | Purpose |
| --- | --- |
| `main.py` | Application entry point |
| `core/` | Capture, parser, filter, flow engine, and remote capture logic |
| `gui/` | Main Qt UI, dialogs, and dashboard code |
| `utils/` | PCAP I/O, system checks, and compile checks |
| `ai/` | AI model artifacts |
| `data/` | Dashboard templates, dashboard storage, and agent package assets |
| `demo/` | Demo capture files |
| `help/` | HTML help pages and user documentation |
| `image/` | UI and topology assets |
| `agent/` | Windows remote capture agent sources |
| `scrap/` | Report sources and research notes |

## Important modules

### `main.py`

Initializes the Qt application, checks the Windows environment when needed, creates the main window, and starts the event loop.

### `gui/application.py`

The main application controller. It connects capture, analysis, dashboard, topology, remote interfaces, preferences, AI export, and many utility dialogs.

### `gui/capture_view.py`

The central capture workspace. It manages packet records, packet list updates, display filters, save/load operations, comments, stream-following views, and related status updates.

### `core/capture.py`

The capture backend for local capture, file-based capture, named pipes, and remote packet streaming.

### `core/parser.py`

Converts Scapy packets into the internal `PacketRecord` model and tracks protocol state, request/response context, and stream metadata.

### `core/formatters.py`

Builds the packet details tree and maps protocol nodes back to the original byte ranges.

### `core/filtering.py`

Implements the display filter engine used by packet filtering, search, and dashboard-related packet scoping.

### `core/flow_engine/`

Contains the flow key, flow model, feature extractor, CSV exporter, model adapter, and behavior analyzer.

### `gui/dashboard/`

Contains dashboard models, repositories, query logic, advanced queries, visualization code, and the dashboard editor.

### `utils/pcap_io.py`

Handles PCAP and PCAPNG load/save operations, metadata, comments, compression, and packet streaming.

### `utils/system_check.py`

Checks Npcap and other platform dependencies.

### `agent/agent_service.py`

Implements the Windows remote capture agent service.

## Data flow

Packetra stores packet data in an internal record model and reuses that model across the UI and analysis pipeline.

1. A capture source provides packets.
2. The parser converts them into `PacketRecord`.
3. The UI shows the packet list, details tree, and bytes.
4. Filters and search narrow the visible packet set.
5. The flow engine groups packets into bidirectional flows.
6. The flow exporter writes CSV output.
7. The AI layer predicts labels and confidence values.
8. The dashboard and topology views present the result in a higher-level form.

## AI state in this repository

The current repo includes AI artifacts under `ai/`, and the runtime path used by the application is defined in `gui/application.py`. The AI pipeline currently works on flows, not on individual packets.

The AI layer performs:

- feature scaling
- model loading
- label decoding
- confidence reporting
- behavior summaries

## PCAPNG metadata

Packetra keeps and updates a subset of PCAPNG metadata, including:

- file comments
- per-packet comments
- interface lists
- section metadata

This helps preserve additional context when a capture file is saved and reopened later.

## Help and documentation

The repository includes HTML help pages under `help/` for:

- the main user guide
- capture workflow
- capture filter usage
- dashboard usage
- search usage
- remote capture guidance

## Environment requirements

- Windows is the primary environment for local live capture
- Linux is supported for remote capture
- Python 3.11 is recommended by the current dependency set
- Npcap is required for local live capture on Windows
- OpenSSH is required for Windows remote capture workflows
- `tcpdump` is required for Linux remote capture

Common Python dependencies include `PySide6`, `scapy`, `psutil`, `paramiko`, `numpy`, `torch`, `scikit-learn`, `joblib`, `lz4`, `pywin32`, and `xgboost`

## Setup and run

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Useful checks

```powershell
python -m py_compile main.py
python utils/compile_project.py
```

## Typical workflows

### Open a capture file

1. Open a `.pcap` or `.pcapng` file.
2. Inspect the packet list.
3. Click a packet to view details and raw bytes.
4. Apply a display filter if needed.
5. Search for packets of interest.

### Start a live capture

1. Select an interface.
2. Set a capture filter if needed.
3. Start capture.
4. Watch packets appear in real time.
5. Stop and save the capture if needed.

### Export flows

1. Load a capture or start a live session.
2. Export flow CSV.
3. Review the resulting CSV file or AI summary.

### Use dashboards

1. Open the dashboard overview.
2. Select a template or create a new dashboard.
3. Bind the dashboard to the current packet scope.
4. Edit widgets, queries, and layout.
5. Save or export the dashboard as JSON.

### Use remote capture

1. Configure the remote host and credentials.
2. Load the remote interface list.
3. Start remote capture.
4. Receive packet data on the local machine.

## Notes

- This README reflects the current codebase layout and runtime flow.
- Some report sources and training notes remain in `scrap/` and are intentionally kept separate from the application code.

