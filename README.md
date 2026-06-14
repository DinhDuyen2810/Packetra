# Packetra

Packetra is a desktop network traffic analysis application built with Python, Scapy, and PySide6. It combines live packet capture, offline PCAP/PCAPNG inspection, protocol dissection, filtering, dashboard-based analysis, remote capture over SSH, and AI-assisted flow classification in a single GUI application.

This README is intentionally written as a full technical guide for the current codebase. It is based on the actual repository structure and the current implementation in `main.py`, `core/`, `gui/`, `utils/`, `ai/`, `data/`, `demo/`, and `docs/full train kaggle.md`.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Core Capabilities](#core-capabilities)
3. [Architecture](#architecture)
4. [Repository Layout](#repository-layout)
5. [Requirements](#requirements)
6. [Installation](#installation)
7. [Running the Application](#running-the-application)
8. [How the UI Works](#how-the-ui-works)
9. [Capture Modes](#capture-modes)
10. [Filtering](#filtering)
11. [Statistics, Analysis, and Investigation Tools](#statistics-analysis-and-investigation-tools)
12. [Dashboards](#dashboards)
13. [AI and Flow Analysis](#ai-and-flow-analysis)
14. [Remote Capture](#remote-capture)
15. [Saving, Loading, and Exporting Data](#saving-loading-and-exporting-data)
16. [Training Pipeline](#training-pipeline)
17. [Model Packaging Used by the App](#model-packaging-used-by-the-app)
18. [Project Data and Assets](#project-data-and-assets)
19. [Troubleshooting](#troubleshooting)
20. [Developer Notes](#developer-notes)

## Project Overview

Packetra is designed as a Wireshark-like packet analysis environment with several custom capabilities:

- Real-time packet capture from local interfaces
- Offline analysis of previously captured traffic
- Display filtering with a custom parser
- Capture filters and capture profile management
- Remote capture over SSH for Linux and Windows hosts
- Conversation analysis and protocol statistics
- Dashboard templates and user dashboards with multiple chart types
- AI-driven per-flow classification using a packaged FT-Transformer TorchScript model
- Rule generation for multiple firewall products from a selected packet
- Demo packet library for testing and teaching
- Built-in HTML help system

The application entry point is [`main.py`](./main.py). On Windows it checks for Npcap before launching the main window.

## Core Capabilities

### Capture and inspection

- Live capture from local interfaces
- Capture filter support
- Promiscuous mode support
- Interface refresh and interface management UI
- Packet list, protocol tree, and packet bytes/hex view
- PCAP and PCAPNG reading
- Real-time updates while packets arrive

### Analysis

- Packet-level display filtering
- Conversations for Ethernet, IPv4, IPv6, TCP, and UDP
- Protocol hierarchy and protocol summaries
- Endpoint and packet-length style statistics
- Flow graph and topology-style investigation tools
- HTTP, IPv4, and IPv6 statistics actions

### Investigation and automation

- AI Analyst workflows on selected traffic
- Flow-based feature extraction and model inference
- Dashboard templates for rapid analysis
- Firewall ACL rule generation from a chosen packet
- Packet comments and metadata-aware save/load flows

### Remote operations

- SSH-based remote capture for Linux using `tcpdump`
- SSH-based remote capture for Windows using `RemoteCaptureAgent.cmd`
- Remote interface listing
- Streaming remote capture output back into the local analyzer

## Architecture

The project is organized around a classic desktop-app split:

- `main.py`
  Starts the Qt application, checks Npcap on Windows, and opens the main window.
- `gui/`
  Contains the main application window, capture views, dialogs, packet panes, dashboard UI, topology UI, and other interactive components.
- `core/`
  Contains capture logic, packet parsing, filtering, formatting, remote capture support, ACL generation, and flow-engine logic.
- `utils/`
  Contains environment checks, PCAP IO helpers, packet-list cache helpers, and parsing utilities.
- `ai/`
  Contains packaged model artifacts used by the runtime inference pipeline.
- `data/`
  Contains dashboard templates and persisted user dashboard data.
- `demo/`
  Contains bundled `.pcapng` demo captures.
- `help/`
  Contains HTML guides opened by the Help menu.
- `docs/`
  Contains draft and research/training documents, including the Kaggle training workflow.

## Repository Layout

```text
Packetra/
|-- main.py
|-- requirements.txt
|-- ai/
|   |-- ft_transformer_torchscript.pt
|   |-- standard_scaler.pkl
|   |-- label_encoder.pkl
|   `-- model_info.json
|-- core/
|   |-- capture.py
|   |-- filtering.py
|   |-- firewall_acl.py
|   |-- parser.py
|   |-- remote_capture.py
|   |-- stream_manager.py
|   `-- flow_engine/
|-- gui/
|   |-- application.py
|   |-- capture_view.py
|   |-- filter_drag.py
|   |-- packet_details.py
|   |-- packet_table.py
|   `-- dashboard/
|-- utils/
|   |-- pcap_io.py
|   |-- pcapng_parser.py
|   |-- system_check.py
|   `-- ...
|-- data/
|   |-- dashboard_templates/
|   `-- dashboards/
|-- demo/
|-- help/
`-- docs/
```

## Requirements

### Python and OS

- Python 3.11 is the safest target for the current dependency set
- Windows is the most fully supported desktop target because the project includes explicit Npcap checks and Windows-specific flows
- Linux is also relevant, especially for remote capture targets

### Python packages

Current `requirements.txt`:

```text
scapy>=2.5.0
PySide6>=6.5.0
psutil>=5.9.0
lz4>=4.3.3
paramiko>=3.4.0
pywin32>=306
numpy>=1.24.0
xgboost>=2.0.0
scikit-learn==1.6.1
joblib>=1.3.0
torch @ https://download.pytorch.org/whl/cpu/torch-2.12.0%2Bcpu-cp311-cp311-win_amd64.whl
```

### Native/runtime requirements

- Windows live capture requires Npcap
- Linux remote capture requires `tcpdump` on the remote host
- Windows remote capture requires `RemoteCaptureAgent.cmd` on the remote host

## Installation

### 1. Clone or extract the project

```bash
git clone <your-repo-url>
cd DATN-Packetra
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Install Npcap on Windows

If you run on Windows and Npcap is missing, the application will warn you at startup. You can also install it manually from <https://npcap.com/>.

The code in [`utils/system_check.py`](./utils/system_check.py) checks:

- `wpcap.dll`
- `Packet.dll`
- `npcap.sys`
- Windows service metadata

## Running the Application

Start the desktop app:

```bash
python main.py
```

At startup:

- Qt logging noise is reduced
- On Windows, Npcap availability is checked
- The main window opens centered and scaled relative to the current screen

## How the UI Works

The main application window is implemented in [`gui/application.py`](./gui/application.py).

### Main menu groups

- `File`
  Open, merge, save, save as, separate/export packets, print, quit
- `Edit`
  Copy, packet search, mark/unmark, ignore/unignore, packet comments, preferences
- `View`
  Toolbar/status bar toggles, packet panes, zoom, packet coloring, column sizing, redissect/reload helpers
- `Go`
  Navigation between packets, conversations, and live capture scrolling
- `Capture`
  Options, start, stop, restart, capture filters, refresh interfaces
- `Analyze`
  Display filter macros, display filter expression, apply as column/filter, conversation filters, follow, expert info
- `Statistics`
  Capture properties, resolved addresses, protocol hierarchy, conversations, endpoints, packet lengths, flow graph, HTTP, IPv4, IPv6
- `Tools`
  AI Analyst, Demo Packet, Network Topology Graph, Dashboard, Firewall ACL Rules
- `Help`
  Version/system info, HTML guides, about dialogs

### Main analysis panes

The capture view is centered around three practical areas:

- Packet table
  One row per packet with summary fields such as packet number, source, destination, protocol, and length
- Packet details tree
  Structured layer-by-layer protocol dissection
- Packet bytes / hex view
  Raw byte inspection for low-level analysis

The capture view also includes extras such as protocol sparklines, list minimap behavior, and filtering widgets.

## Capture Modes

### Local live capture

The local sniffer logic lives in [`core/capture.py`](./core/capture.py). It uses Scapy capture primitives and also supports decoding multiple link-layer cases, including Ethernet, Linux cooked capture, and specific mPacket-like framed inputs.

Capabilities include:

- Selecting an interface from the UI
- Applying a capture filter before starting
- Promiscuous or non-promiscuous operation
- Resolving interface identities for packet matching
- Reading from live sources or files

### Offline capture analysis

The app can load existing packet captures and inspect them interactively. Utilities in `utils/pcap_io.py` and `utils/pcapng_parser.py` support save/load workflows and metadata-aware operations.

### Demo capture mode

The `Tools -> Demo Packet` feature uses bundled `.pcapng` files from `demo/001.pcapng` through `demo/100.pcapng`. This is useful for demos, teaching, and regression testing.

## Filtering

Packetra has two different filter concepts. They serve different purposes and should not be mixed up.

### Capture filters

Capture filters limit what gets captured before packets enter the local session. These are configured from the capture workflow and the `Capture Filters...` dialog in the Capture menu.

In `gui/application.py`, capture filters can be:

- Entered directly when configuring capture options
- Stored as presets with name, filter expression, and comment
- Validated before capture starts
- Applied to interfaces and remembered as part of capture settings

Use capture filters when you want to reduce traffic volume up front.

Examples:

```text
tcp
udp port 53
host 192.168.1.10
port 443
net 10.0.0.0/24
```

### Display filters

Display filters work after packets are already loaded into the UI. The implementation is in [`core/filtering.py`](./core/filtering.py).

Supported behavior includes:

- Boolean logic with `and`, `or`, `not`
- Symbolic logic with `&&`, `||`, `!`
- Parentheses
- Comparisons with `==`, `!=`, `<`, `>`, `<=`, `>=`
- String search using `contains`
- Protocol-only fast-path filters such as `tcp`, `arp`, `ipv6`

#### Supported protocol aliases

The current parser recognizes protocol aliases including:

```text
tcp, udp, dns, mdns, arp, icmp, icmpv6, igmp, tls, quic, http, smtp, imf,
dhcp, bootp, ripng, ripv2, stp, syslog, ntp, lacp, vtp, dtp, lldp, udld,
loop, hsrp, hsrpv2, ip, ipv6, eth, tftp, ssdp, esp, ssh, sshv2, isakmp, ike,
ftp, pop, imap, smb, smb2, llmnr, nbns, snmp, ah, ospf, eigrp, bgp, gre, vlan,
ssl, ipv4, icmpv4
```

#### Supported fields visible in the parser

Current field families implemented in `DisplayFilter._resolve_field_values()` include:

- Frame:
  `frame.number`, `frame.len`, `frame.time_delta`
- Generic summary:
  `length`, `len`, `protocol`, `proto`, `src`, `source`, `dst`, `destination`
- Ethernet:
  `eth.addr`, `eth.src`, `eth.dst`, `eth.type`
- VLAN:
  `vlan.id`
- ARP:
  `arp.opcode`, `arp.src.proto_ipv4`, `arp.dst.proto_ipv4`
- IPv4:
  `ip.addr`, `ip.host`, `ip.src`, `ip.dst`, `ip.proto`, `ip.ttl`
- IPv6:
  `ipv6.addr`, `ipv6.host`, `ipv6.src`, `ipv6.dst`
- ICMP:
  `icmp.type`
- TCP:
  `tcp.port`, `tcp.srcport`, `tcp.dstport`, `tcp.stream`, `tcp.flags.*`
- UDP:
  `udp.port`, `udp.srcport`, `udp.dstport`, `udp.stream`

#### Example display filters

```text
tcp
udp and udp.port == 53
ip.src == "192.168.1.10"
ip.addr == "8.8.8.8"
frame.len > 1000
tcp.flags.syn and not tcp.flags.ack
http or tls
dns contains "google"
(tcp.port == 80 or tcp.port == 443) and ip.dst == "10.0.0.5"
```

### Ways users can create or apply filters from the UI

Based on the current code, users can create filters through multiple UI paths:

- Type a display filter manually into the filter bar
- Press Enter or the apply action after entering a filter
- Open `Analyze -> Display Filter Macros...`
- Open `Analyze -> Display Filter Expression...`
- Use `Analyze` actions that apply generated filters
- Drag packet-derived filter expressions into the filter input
- Use packet-table derived expressions from [`gui/filter_drag.py`](./gui/filter_drag.py)

The current drag-derived expressions include:

- From `Source` column: `src == "value"`
- From `Destination` column: `dst == "value"`
- From `Protocol` column: `protocol == "value"`
- From `Length` column: `frame.len == value`

This is important because filtering in Packetra is not only text-entry based; some filters are generated contextually from packet data.

## Statistics, Analysis, and Investigation Tools

### Conversations

[`gui/conversations_dialog.py`](./gui/conversations_dialog.py) builds conversation summaries for:

- Ethernet
- IPv4
- IPv6
- TCP
- UDP

Each conversation tracks counts and byte totals in both directions, plus first/last timestamps.

### Firewall ACL rule generation

`Tools -> Firewall ACL Rules` generates rules from a selected packet. The implementation is in [`core/firewall_acl.py`](./core/firewall_acl.py).

Supported target products include:

- Cisco IOS ACL
- IP Filter (`ipfilter`)
- IPFirewall (`ipfw`)
- Netfilter (`iptables`)
- Packet Filter (`pf`)
- Windows Firewall `netsh` old syntax
- Windows Firewall `netsh` new syntax

The generator can build rules from fields such as:

- Source MAC
- Destination MAC
- Source IPv4
- Destination IPv4
- Source/destination TCP port
- Source/destination UDP port
- IPv4 plus port combinations
- Full IPv4 pair and port-pair combinations

### Topology and graph-style tools

The main window includes a network topology graph tool implemented with `QGraphicsView`-based graph items in `gui/application.py`.

### Demo packet library

The application can load bundled demonstration captures to help validate parsing and teach workflows without needing a live network.

## Dashboards

The dashboard system is one of the major differentiators in this project.

### Dashboard subsystem

Main components:

- [`gui/dashboard/models.py`](./gui/dashboard/models.py)
- `gui/dashboard/services.py`
- `gui/dashboard/query_engine.py`
- `gui/dashboard/repository.py`
- `gui/dashboard/visualization.py`
- `gui/dashboard/dashboard_overview.py`
- `gui/dashboard/dashboard_editor.py`

### Dashboard concepts

- Dashboards are saved as JSON-backed configuration objects
- Dashboards can be templates or user dashboards
- Each dashboard contains widgets
- Each widget defines:
  - data source
  - query
  - visualization
  - layout

### Supported visualization types

Current enum values include:

```text
metric
table
bar
horizontal_bar
line
area
scatter
radar
treemap
sunburst
pie
donut
histogram
heatmap
topology
```

### Query model capabilities

Widgets can define:

- `filter`
- `group_by`
- `metrics`
- `sort`
- `limit`
- `time_bucket`
- `columns`

Metric types supported by the dashboard model include:

- `count`
- `sum`
- `avg`
- `min`
- `max`
- `distinct_count`

### Dashboard templates shipped with the project

The repository currently includes:

- `template_dns_analysis.json`
- `template_endpoint_activity.json`
- `template_http_tls_analysis.json`
- `template_network_overview.json`
- `template_protocol_analysis.json`
- `template_security_investigation.json`
- `template_timeline_analysis.json`
- `template_topology_view.json`

### Runtime dashboard flow

When `Tools -> Dashboard` is opened:

- The app checks that capture data exists
- Template and user repositories are initialized
- Data sources for the current capture session are registered
- The visualization registry is created
- A `DashboardService` instance is created
- The overview/gallery dialog opens

### Stored dashboard data

- Templates are read from `data/dashboard_templates/`
- User dashboards are stored under `data/dashboards/`

## AI and Flow Analysis

The AI pipeline is located mainly under `core/flow_engine/`.

### Runtime components

- `feature_extractor.py`
  Builds structured flow features from packet streams
- `flow.py` and `flow_key.py`
  Define flow state and keys
- `behavior_analyzer.py`
  Higher-level behavioral analysis support
- `csv_exporter.py`
  Exports packet/flow data to CSV
- `model_adapter.py`
  Loads and runs ML models

### Model adapter behavior

`PacketraModelAdapter` currently supports:

- TorchScript `.pt` model loading
- XGBoost JSON model loading
- Optional feature-column order handling
- Label recovery from:
  - `label_encoder.pkl`
  - `model_info.json`
  - fallback labels

The TorchScript path is the main packaged path used by the repository.

### Packaged model information

Current packaged metadata from `ai/model_info.json`:

- Model type: `FTTransformer TorchScript`
- Number of features: `77`
- Number of classes: `53`
- Input dtype: `float32`

The packaged classes include `Benign` and many attack families such as `DDoS`, `PortScan`, `DoS Hulk`, `SSH`, `DrDoS` variants, web attacks, and exploit-related labels.

### Inference flow

At runtime, the application:

1. Extracts flow-level features from packets
2. Orders features to match the training schema
3. Applies the saved `StandardScaler`
4. Runs the TorchScript model on CPU
5. Converts logits into predicted labels
6. Shows per-flow results in AI Analyst workflows

## Remote Capture

Remote capture support is implemented in [`core/remote_capture.py`](./core/remote_capture.py).

### SSH client behavior

The code uses Paramiko and caches shared SSH clients by:

- host
- port
- username
- remote OS type
- auth type

### Linux remote capture

For Linux targets, Packetra runs:

```text
tcpdump -D
tcpdump -n -s 0 -i '<iface>' -U -w -
```

Meaning:

- `tcpdump -D` lists interfaces
- `-s 0` captures full packets
- `-U` flushes output as packets arrive
- `-w -` streams capture bytes to stdout

If promiscuous mode is disabled, `-p` is added.

### Windows remote capture

For Windows targets, the code expects `RemoteCaptureAgent.cmd` and looks in:

- `C:\RemoteCaptureAgent\RemoteCaptureAgent.cmd`
- `C:\Program Files\RemoteCaptureAgent\RemoteCaptureAgent.cmd`
- or PATH fallback

Commands are wrapped through `cmd.exe` for reliable behavior in OpenSSH sessions.

### What the app can do remotely

- Connect to the host through SSH
- List remote interfaces
- Start a remote capture stream
- Apply a remote capture filter
- Stream packets back into the local GUI session

## Saving, Loading, and Exporting Data

The project contains several save/export paths:

- Save capture file
- Save capture file with metadata
- Save PCAPNG comments
- Save packet comments
- Export specified packets
- Export flow/packet data to CSV through the flow-engine tools

Relevant helpers are in `utils/pcap_io.py` and `core/flow_engine/csv_exporter.py`.

## Training Pipeline

This section summarizes the model-training workflow documented in [`docs/full train kaggle.md`](./docs/full%20train%20kaggle.md). That document is the authoritative project note for dataset preparation, training, evaluation, and packaging.

### Dataset source used in the training notebook

The training document uses:

```text
/kaggle/input/datasets/inhngcduyn/datasetids/final.csv
```

### Dataset summary from the training document

- Total rows: `3,012,112`
- Total columns: `78`
- Feature columns: `77`
- Label column: `Label`
- Number of classes: `53`

### Reporting outputs created during dataset inspection

The notebook creates:

- `columns_units.csv`
- `label_counts.csv`
- `final_dataset_report.csv`
- `label_distribution_donut.png`

### Preprocessing flow

The training document performs these high-level steps:

1. Load the full CSV
2. Strip label names
3. Split features from `Label`
4. Convert all feature columns to numeric
5. Replace `inf` values with `NaN`
6. Fill missing values with `0`
7. Cast feature matrix to `float32`
8. Encode labels with `LabelEncoder`
9. Perform stratified `train_test_split`
10. Fit `StandardScaler`
11. Convert data to PyTorch tensors
12. Train using DataLoaders

### Model architecture used in training

The training document defines an FT-Transformer style classifier with:

- `77` numerical features
- `53` output classes
- `d_token = 192`
- `n_blocks = 6`
- `n_heads = 8`
- `dropout = 0.1`

Reported parameter count:

- `2,762,357`

### Optimization and training strategy

From the training document:

- Loss: `FocalLoss(gamma=2.0)`
- Optimizer: `AdamW`
- Learning rate: `1e-4`
- Weight decay: `1e-4`
- Scheduler: `CosineAnnealingLR(T_max=20)`
- Mixed precision: yes
- Epochs: `20`
- Batch size: `2048`

### Training outputs

Saved artifacts include:

- `best_ft_transformer_checkpoint.pt`
- `best_ft_transformer.pt`
- `last_ft_transformer_checkpoint.pt`
- `training_history.csv`

### Reported training result in the project note

The document reports:

- Best epoch: `18`
- Best macro F1: `0.644135`

This is the metric history that led to the exported deployment package currently used by the app.

## Model Packaging Used by the App

The Kaggle document also describes how the deployable inference package is produced.

### Packaging outputs

The package contains:

- `ft_transformer_torchscript.pt`
- `standard_scaler.pkl`
- `label_encoder.pkl`
- `model_info.json`
- zipped archive version of the package

### Important packaging detail

The training note explicitly recreates the `StandardScaler` before export because the original variable name had been overwritten by PyTorch `GradScaler`. That detail matters if you reproduce training and packaging exactly as documented.

### Files currently committed under `ai/`

- `ft_transformer_torchscript.pt`
- `ft_transformer_torchscript_package.zip`
- `standard_scaler.pkl`
- `label_encoder.pkl`
- `model_info.json`

## Project Data and Assets

### `data/`

- Dashboard templates
- User dashboard persistence data

### `demo/`

- 100 demo `.pcapng` captures for teaching and testing

### `help/`

Current help files include:

- `index.html`
- `user_guide.html`
- `capture_workflow.html`
- `capture_filter_guide.html`
- `filter_reference.html`
- `dashboard_guide.html`
- `agent_guide.html`

These are opened from the Help menu in the GUI.

## Troubleshooting

### Windows capture does not start

Check:

- Npcap is installed
- Npcap service and driver files exist
- The application has enough permissions
- Another packet-capture tool is not holding resources unexpectedly

### Remote Linux capture fails

Check:

- SSH connectivity works
- The username is correct
- `tcpdump` is installed
- The remote user has permission to run `tcpdump`
- The interface name returned by `tcpdump -D` is valid

### Remote Windows capture fails

Check:

- OpenSSH is working on the remote host
- `RemoteCaptureAgent.cmd` exists in one of the expected paths
- The SSH user can run the agent
- The interface name is valid on that host

### AI inference fails

Check:

- All files under `ai/` exist
- The feature count still matches the training schema
- The `scikit-learn`, `joblib`, and `torch` runtime versions are compatible with the exported artifacts

### Display filters do not behave like Wireshark

Packetra uses a custom display filter parser, not Wireshark's full grammar. The currently supported fields and protocol aliases are the ones implemented in `core/filtering.py`.

## Developer Notes

### Key implementation files to study first

- [`main.py`](./main.py)
- [`gui/application.py`](./gui/application.py)
- [`gui/capture_view.py`](./gui/capture_view.py)
- [`core/capture.py`](./core/capture.py)
- [`core/filtering.py`](./core/filtering.py)
- [`core/remote_capture.py`](./core/remote_capture.py)
- [`core/firewall_acl.py`](./core/firewall_acl.py)
- [`core/flow_engine/model_adapter.py`](./core/flow_engine/model_adapter.py)

### Current project character

This repository is not just a simple packet sniffer. It is a hybrid of:

- desktop analyzer
- protocol viewer
- capture manager
- dashboard platform
- remote acquisition tool
- ML-assisted traffic classifier

If you extend the project, keep those five layers aligned:

- packet acquisition
- packet parsing and display
- interactive analysis
- persisted artifacts and exports
- AI/flow analytics

## Related Beginner Guide

For a step-by-step beginner-friendly installation and packaging walkthrough, open [`README.html`](./README.html) in a browser.
