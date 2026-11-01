# Security Operations Platform

A local-first platform for importing security events, investigating a manually selected dataset, reviewing remediation proposals, and recording simulated outcomes. The project includes a responsive operational dashboard served by the local FastAPI application.

## Architecture

The initial backend foundation uses Python, SQLite, and Pydantic. `backend/config.py` loads environment settings; `backend/database.py` opens configured SQLite connections and initializes the schema in `backend/schema.sql`. The schema separates immutable-source event records from processed records and includes supporting tables for datasets, investigations, findings, authorizations, audit, feedback, and evaluation labels.

The database file is local under `data/database/` by default and is ignored by Git. The dashboard is a static, framework-free interface under `dashboard/`; API data remains in the local database.

## Setup

1. Create and activate a Python 3.11+ virtual environment.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and adjust settings as needed.
4. Initialize the SQLite database:

   ```powershell
   python -c "from backend.config import get_settings; from backend.database import initialize_database; initialize_database(get_settings().database_path)"
   ```

`SOP_DATABASE_PATH` sets the database file, `SOP_LOG_LEVEL` sets the application log level, and `SOP_LLM_PROVIDER` defaults to `mock`. `SOP_LLM_API_KEY` is optional and must be supplied through the environment if a future provider requires it.

## Dataset library

`data/datasets/manifest.json` indexes three selectable synthetic datasets, with 2,000 events each. Each dataset has an `events.jsonl` file and a separate `ground_truth.jsonl` evaluation file. Its manifest records synthetic provenance, event counts, source types, and SHA-256 checksums. The event library covers Windows, Linux, network/firewall, cloud, web application, endpoint, and email/identity sources. Severity distribution across all 6,000 events is 5% critical, 10% high, 25% medium, 35% low, and 25% informational.

All current library events are generated synthetic data; no public dataset content has been imported. Do not expose `ground_truth.jsonl` to investigation agents or normal investigation views. Rebuild the library with `python scripts/generate_synthetic_datasets.py`; use `--output-dir` to write elsewhere or `--events-per-dataset` with a multiple of 20 to change its size.

## Tests

Run the foundation tests with `python -m pytest`.

## Local API

After installing dependencies and initializing the database, run `python -m uvicorn backend.api:app --host 127.0.0.1`. On startup, the API registers the three manifest datasets and loads their checked-in JSONL events into the original-event store if any are missing. The current API exposes dataset listing/detail, paginated dataset-scoped event search, JSONL/JSON/CSV import to an explicitly named dataset, explicit investigation creation, and an explicit investigation run endpoint. Create an investigation with `POST /api/datasets/{dataset_id}/investigations`, then run it with `POST /api/investigations/{investigation_id}/run`. The three agents run in sequence and only generate findings, hunts, and proposals; they do not execute remediation.

The local deterministic mock provider is the only implemented provider. It uses versioned prompts and validated structured outputs. Investigation agents receive a read-only SQLite view bound to the selected dataset, and their event searches are restricted to that view. Ground-truth tables are not part of the agent data interface.

## Dashboard

The local dashboard is served from the same application at `http://127.0.0.1:8000/`. It has nine sections: Overview, Dataset Library, Investigations, Threat Findings, Response Approvals, Processed Logs, Audit History, Reports, and Settings. Dataset selection, investigation start, human decisions, and simulation execution are all explicit user actions. The interface includes persistent dark and light themes and uses inline Tabler-style SVG icons; its CSS declares Source Sans 3 and IBM Plex Mono as preferred local fonts with system fallbacks for machines where those fonts are not installed. Charts and counts are populated from dashboard API queries; synthetic records are identified as synthetic.

Response proposals are validated by the local policy engine before approval. Reviewers can approve, deny, or modify a proposal through `POST /api/proposals/{proposal_id}/decisions`; approval history is available at `/api/proposals/{proposal_id}/approvals`. The policy checks the allowlisted action, cited original event, evidence-backed target, severity, and confidence. Approval records do not execute actions; execution remains simulation-only and is handled by the later remediation phase.

After a final approved decision, request a simulation with `POST /api/proposals/{proposal_id}/executions`, a JSON body containing the `approval_id`, and a unique `Idempotency-Key` header. Repeating the same key returns the original execution record. A proposal/approval pair can execute only once. Execution produces a separate processed-event snapshot; the original event remains unchanged. Retrieve the record at `/api/executions/{execution_id}` and its before/after comparison at `/api/executions/{execution_id}/comparison`.

## Data handling

The database stores normalized event and raw-event JSON separately. Dataset provenance and source checksums have dedicated fields. The schema includes hidden ground-truth labels for evaluation; investigation services must not expose that table to agents or normal dashboard/API responses.
