# DATN-Packetra

## 1. Introduction

`DATN-Packetra` is a desktop network analysis application built with Python and PySide6. It is designed for study, demonstrations, packet inspection, flow-based traffic analysis, and AI-assisted anomaly interpretation inside a single GUI.

The project is aimed at:

- students learning packet analysis
- users who need a simpler learning path than Wireshark for selected workflows
- researchers working with PCAP-to-flow-to-CSV pipelines
- demo and lab environments that need packet inspection, topology, dashboards, and AI analysis together

Packetra is not only a capture viewer. It combines multiple analysis layers in one application:

- packet-level inspection
- flow extraction
- CSV export
- dashboard visualization
- topology visualization
- demo capture workflows
- remote capture
- AI Analyst for flow-based behavioral analysis

## 2. Project Goals

The project targets the following outcomes:

- make packet capture analysis easier to approach for new users
- combine packet-level and flow-level analysis in one GUI
- support the pipeline `PCAP -> Flow -> CSV -> AI prediction`
- provide visual summaries through dashboards and topology
- support demo scenarios for teaching and presentations
- provide a foundation for more explainable AI-assisted traffic analysis

## 3. Problem Statement

Many beginners can open a capture file but still struggle to answer practical questions such as:

- what happened in this traffic?
- which flows are normal and which are suspicious?
- is this behavior an attack, and if so, what type?
- how can the result be explained clearly to a non-expert?

Packetra addresses that gap by:

- showing packets in a familiar table-driven workflow
- parsing packets into readable protocol trees
- aggregating packets into flows
- exporting AI-ready flow features
- running model inference on extracted flows
- presenting results through summaries, dashboards, and topology

## 4. Main Features

### 4.1 Packet Analysis

- Open `.pcap` and `.pcapng` files.
- Start and stop live capture.
- View packet list, packet details, and packet bytes.
- Search, filter, mark, ignore, comment, follow stream, and copy data.
- Use transport, MAC, and network name resolution options.
- Export or split packet subsets into new capture files.

### 4.2 Flow Analysis

- Group packets into flows through the internal flow engine.
- Export flow features to CSV.
- Support CIC-style feature extraction for downstream ML workflows.
- Analyze selected packets, filtered packets, or entire captures.

### 4.3 AI Analyst

- Run behavioral analysis on extracted flows.
- Display action summaries and model predictions.
- Help correlate packet evidence with flow-level results.
- Support demo workflows for malicious or benign traffic examples.

### 4.4 Dashboard

- Built-in dashboard templates.
- User dashboards stored separately from templates.
- Create, rename, edit, save, import, and export dashboards.
- Multiple widget types for protocol mix, timelines, top talkers, conversations, and more.

### 4.5 Topology

- Visualize host-to-host relationships.
- Show traffic edges and communication patterns.
- Help explain who is talking to whom at a glance.

### 4.6 Demo Packet

- Load demo captures from `demo/`.
- Select demos by action name instead of numeric ID only.
- Use demo traffic for teaching, testing, and UI walkthroughs.

### 4.7 Remote Capture

- Remote Linux capture over SSH with `tcpdump`.
- Remote Windows capture through the Packetra remote agent flow.
- Remote interface management inside the GUI.

### 4.8 Help and HTML Documentation

The `help/` folder contains end-user documentation in HTML, including:

- general user guide
- capture workflow guide
- capture filter guide
- display filter reference
- dashboard guide
- remote capture guide

## 5. High-Level Architecture

Packetra can be understood as five layers:

1. Input layer
   - local live capture
   - remote capture
   - open saved PCAP/PCAPNG files
   - demo capture loading

2. Packet analysis layer
   - packet parsing
   - packet list rendering
   - detail tree generation
   - byte/hex rendering
   - display filtering and search

3. Flow analysis layer
   - flow grouping
   - feature extraction
   - CSV export

4. AI layer
   - model loading
   - preprocessing and scaling
   - inference
   - summary generation

5. Presentation layer
   - dashboards
   - topology
   - dialogs, reports, and summaries

### Overall Workflow

```text
Capture or open file
-> Parse packets
-> Show packet list / details / bytes
-> Group packets into flows
-> Export or analyze features
-> Run AI prediction
-> Present results in tables, summaries, dashboards, and topology
```

## 6. Folder Structure

### 6.1 Top-Level Layout

| Path | Purpose |
| --- | --- |
| `ai/` | Model artifacts, scaler, metadata, label definitions |
| `core/` | Parsing, formatting, filtering, flow engine, AI backend logic |
| `data/` | Dashboard templates and user dashboard data |
| `demo/` | Demo capture files and demo metadata |
| `docs/` | Supporting project documents and research notes |
| `gui/` | Full PySide6 user interface |
| `help/` | HTML end-user documentation |
| `image/` | Icons and UI assets |
| `utils/` | Capture IO, system checks, helper utilities |
| `agent/` | Remote capture agent packaging and related files |
| `main.py` | Application entry point |
| `README.html` | Quick-start HTML guide |
| `README.md` | Project overview and technical documentation |

### 6.2 Important Source Files

| File | Role |
| --- | --- |
| `main.py` | Starts the application, performs environment checks, opens the main window |
| `gui/application.py` | Main application controller and menu/action wiring |
| `gui/capture_view.py` | Packet table, packet details, bytes view, filter, save/load, capture flow |
| `gui/dashboard/` | Dashboard overview, editor, services, visualization |
| `core/parser.py` | Packet parsing and protocol inference |
| `core/formatters.py` | Packet summary tree, detail formatting, display helpers |
| `core/filtering.py` | Display-filter engine |
| `core/flow_engine/feature_extractor.py` | Flow extraction and feature generation |
| `core/flow_engine/model_adapter.py` | Model loading and inference |
| `utils/pcap_io.py` | Capture read/write and metadata helpers |
| `utils/system_check.py` | Npcap and environment diagnostics |

## 7. Core Concepts

### 7.1 Packet

A packet is the smallest network unit Packetra works with directly when reading a capture or consuming live traffic.

### 7.2 PCAP / PCAPNG

These are the raw capture file formats Packetra opens and saves.

- `PCAP` is the classic capture format.
- `PCAPNG` supports richer metadata such as comments and interface information.

### 7.3 Flow

A flow is a logical communication unit built from packets that share transport and endpoint characteristics. Flow-based analysis provides better behavioral context than isolated packets.

### 7.4 Flow CSV

This is the exported tabular representation of extracted flows. Each row represents one flow, not one packet.

### 7.5 Label

A label is the target class used by training or prediction, for example:

- `Benign`
- `DDoS`
- `PortScan`
- `DoS Hulk`
- `Web Attack - SQL Injection`

### 7.6 Feature

Features are the numeric or categorical inputs consumed by the AI model, such as:

- flow duration
- packet counts
- byte counts
- inter-arrival time statistics
- TCP flag counts
- segment length metrics

## 8. Dataset and Training Data

Packetra follows a flow-based IDS workflow. The project is aligned with CIC-style datasets and schemas, especially the academic direction of `CIC-IDS-2017` and related derived flow data.

Important reminder:

- the AI workflow is flow-based
- each CSV row is one flow
- packet captures are first converted into structured flows before AI inference

The training reference process is documented in:

- `docs/full train kaggle.md`

That document describes the research-side training workflow used to produce the current inference artifacts.

## 9. AI Model Status

This is a critical point for accuracy when describing the current repository state.

Older project descriptions may mention XGBoost, but the artifacts currently committed in the repository indicate that the active packaged inference path is based on an FT-Transformer TorchScript model running on CPU.

At the same time:

- `requirements.txt` still includes libraries that support broader experimentation
- `core/flow_engine/model_adapter.py` still contains logic flexible enough to support other model forms
- the repository contains AI metadata and preprocessing assets that must stay consistent with the feature schema

### AI Artifacts in `ai/`

Typical project artifacts include:

- `feature_columns.json`
- `label_encoder.pkl`
- `standard_scaler.pkl`
- `model_info.json`
- model weights or scripted model files

### Why `feature_columns.json` Matters

For any flow-based model, feature order is mandatory. If the exported feature columns are out of order, missing, or schema-incompatible with training, predictions can become meaningless.

## 10. PCAP -> Flow -> CSV -> AI Pipeline

### Step 1: Read capture data

The user can:

- start live capture
- open a saved file
- load a demo capture

### Step 2: Parse packets

`core/parser.py` converts raw packets into structured records with fields such as:

- number
- time
- source
- destination
- protocol
- length
- info
- metadata

### Step 3: Build flows

`FlowFeatureExtractor` groups packets into flows and computes flow statistics.

### Step 4: Export flow features

Packetra can export the derived flows to CSV for inspection, research, or model input.

### Step 5: Normalize features

Before inference:

- missing values are handled
- numeric conversion is applied
- infinities and invalid values are cleaned
- scaling is applied through the stored scaler
- columns are aligned to the required feature order

### Step 6: Run prediction

The AI layer:

- loads the packaged model
- converts features to the model input format
- predicts labels
- returns summaries and class counts

### Step 7: Present results

Results can appear in:

- AI Analyst dialogs
- CSV outputs
- dashboard widgets
- topology workflows
- packet-level drill-down sessions

## 11. Dashboard System

### Main Dashboard Capabilities

- built-in templates
- user dashboards
- widget editing
- import/export through JSON
- persistent local storage

### Dashboard Data Files

| File | Role |
| --- | --- |
| `data/dashboards/templates/*.json` | Built-in templates |
| `data/dashboards/user_dashboards.json` | User-created dashboards |

### Import / Export

The current build supports importing dashboards from JSON and exporting existing dashboards back to JSON. Sample import structures are documented in `help/dashboard_guide.html`.

## 12. Network Topology

The topology view is used to visualize communication between endpoints.

It helps users:

- identify active hosts
- inspect edges between nodes
- understand traffic concentration
- explain attack scenarios more visually

## 13. Demo Packet

Demo Packet exists to:

- showcase representative actions and scenarios
- support classrooms and demonstrations
- provide fast test data for GUI features

When the user selects a demo action:

- Packetra opens the matching capture from `demo/`
- the action name is shown clearly
- packet list, AI Analyst, dashboards, and topology can all be explored on that dataset

## 14. Environment Setup

### Requirements

- Windows is the primary local-capture target
- Python 3.10+ is recommended
- Npcap is required for local live capture on Windows

### Typical Setup

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

### Project Compile Check

```powershell
python -m py_compile main.py
python utils/compile_project.py
```

### Npcap

`main.py` checks for Npcap on Windows startup. If it is missing, Packetra warns the user because local capture cannot start without it.

## 15. Common Usage Paths

### GUI Usage

Typical end-user flow:

1. Open a capture or start live capture.
2. Inspect packet list, details, and bytes.
3. Apply display filters.
4. Follow streams or use search.
5. Run AI Analyst or export flow CSV.
6. Use dashboard or topology for summary views.
7. Save, export, split, or merge captures if needed.

### Remote Capture

Remote capture is integrated into the GUI.

- Linux remote capture uses SSH plus `tcpdump`.
- Windows remote capture uses the Packetra agent workflow in `agent/`.

Detailed end-user instructions are in `help/agent_guide.html`.

## 16. Model Training

The current repository does not expose a single ready-to-run `train.py` at the root that reproduces the full research pipeline end to end.

Instead, the training story is represented by:

- the committed inference artifacts in `ai/`
- the project code that consumes those artifacts
- the research/training notes in `docs/full train kaggle.md`

### Training Flow from the Reference Document

The documented training process includes:

1. loading and combining dataset sources
2. cleaning and normalizing labels
3. selecting the target feature schema
4. balancing or quota-controlling training data
5. splitting data for training and evaluation
6. training the model
7. evaluating accuracy, macro F1, and confusion matrix
8. exporting model and preprocessing artifacts

### Expected Training Outputs

The project expects training outputs such as:

- model artifact
- scaler
- label encoder
- feature column list
- model metadata

## 17. Prediction with Trained Models

In the current application, prediction is primarily driven through the GUI:

1. open or capture traffic
2. build flows
3. extract feature rows
4. scale and align features
5. run inference
6. show summaries and labels

If a different model is introduced later, its preprocessing contract must still match the expected feature schema.

## 18. Current Results

The repository includes the packaged inference path and the surrounding infrastructure needed to:

- parse packet captures
- extract flows
- export CSV
- run AI inference
- visualize outputs in the GUI

Reference training metrics and academic discussion remain tied to the training notes in `docs/full train kaggle.md`.

## 19. Limitations

- The active AI workflow is strongly tied to CIC-style flow schemas.
- Feature order and schema must match the trained artifact exactly.
- The repository does not yet provide a fully reproducible one-command training pipeline at the root.
- Real-world generalization still depends on further evaluation outside the original training environment.
- Rare or behaviorally overlapping classes may still be unstable.
- Some advanced workflows remain GUI-first rather than CLI-first.

## 20. Future Work

- make the training pipeline reproducible directly inside the repository
- improve schema documentation for the flow engine
- expand explainable AI output
- improve large-capture dashboard performance
- extend selective packet-to-flow conversion workflows
- strengthen evaluation on real-world traffic
- simplify packaging and onboarding for new users

## 21. Frequently Asked Questions

### Does this project analyze packets or flows?

Both. Packets are the raw evidence layer; flows are the behavioral analysis layer.

### Why does the AI not classify individual packets directly?

Because common IDS datasets and behavior models rely on flow context rather than isolated packets.

### Is each CSV row a packet or a flow?

In Packetra's AI pipeline, each CSV row is one flow.

### Does the project use CICFlowMeter?

The project is aligned with CIC-style schemas and also includes its own flow engine implementation under `core/flow_engine/`.

### Is the current repository using XGBoost or FT-Transformer?

The currently committed inference artifacts point to FT-Transformer TorchScript as the real packaged inference path, even though older descriptions may mention XGBoost.

### Can I use Packetra without AI?

Yes. Packetra is still useful as a packet capture viewer and analysis tool even if AI Analyst is never used.

### Is remote capture required?

No. Remote capture is optional.

## 22. Conclusion

Packetra is an academic-minded but practical network analysis project. Its core value is the way it connects the full chain:

```text
capture data
-> parse packets
-> build flows
-> export structured features
-> run AI inference
-> present readable visual results
```

For a new reader, this README should answer the essential questions:

- what the project does
- how the main modules are organized
- how packet and flow analysis fit together
- how AI inference is integrated
- what is required to run the application
- where training information currently lives
- what the current limitations and future directions are

