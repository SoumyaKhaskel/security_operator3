"""FastAPI application factory for dataset-scoped backend APIs."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
import uuid
from typing import Literal
import csv
import io
import json

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, model_validator

from agents.orchestrator import InvestigationNotFoundError, InvestigationOrchestrator, InvestigationStateError
from agents.providers import configured_provider
from backend.config import get_settings
from backend.dashboard_data import DashboardDataService
from backend.database import database_session, initialize_database
from backend.services.datasets import DatasetNotFoundError, DatasetService
from backend.services.events import EventService
from backend.services.investigations import InvestigationService
from ingestion.normalizer import MAX_FILE_BYTES
from ingestion.service import IngestionService
from policy_engine.review import (
    PolicyRejectedError,
    ProposalDecisionConflict,
    ProposalNotFoundError,
    ProposalReviewService,
)
from remediation_worker.worker import (
    ExecutionConflict,
    ExecutionNotAuthorized,
    ExecutionNotFoundError,
    SimulationRemediationWorker,
)


class InvestigationRequest(BaseModel):
    requested_by: str = Field(min_length=1, max_length=128)


class ProposalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "denied", "modified"]
    reviewer: str = Field(min_length=1, max_length=128)
    comment: str = Field(default="", max_length=2000)
    action_type: Literal["isolate_host", "disable_account", "block_ip", "monitor"] | None = None
    target_type: Literal["host", "account", "ip"] | None = None
    target_value: str | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def validate_change_fields(self):
        changes = (self.action_type, self.target_type, self.target_value)
        if self.decision == "modified" and all(value is None for value in changes):
            raise ValueError("modified decisions require at least one change")
        if self.decision != "modified" and any(value is not None for value in changes):
            raise ValueError("change fields are allowed only with a modified decision")
        return self


class ExecutionRequest(BaseModel):
    approval_id: str = Field(min_length=1, max_length=128)


def create_app(database_path: str | Path | None = None, library_dir: str | Path | None = None) -> FastAPI:
    settings = get_settings()
    db_path = Path(database_path or settings.database_path)
    datasets_path = Path(library_dir or Path(__file__).resolve().parents[1] / "data" / "datasets")
    dataset_service = DatasetService(datasets_path, db_path)
    dashboard_data = DashboardDataService(db_path, dataset_service, settings)
    event_service = EventService(db_path, dataset_service)
    investigation_service = InvestigationService(db_path, dataset_service)
    proposal_review_service = ProposalReviewService(db_path)
    remediation_worker = SimulationRemediationWorker(db_path, proposal_review_service)
    orchestrator = InvestigationOrchestrator(db_path, configured_provider(settings.llm_provider))
    ingestion_service = IngestionService(
        db_path,
        db_path.parent.parent / "quarantine",
        dataset_service,
    )
    staging_dir = db_path.parent.parent / "import_staging"

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        initialize_database(db_path)
        dataset_service.register_library()
        for dataset in dataset_service.list_datasets():
            with database_session(db_path) as connection:
                event_count = connection.execute(
                    "SELECT count(*) FROM original_events WHERE dataset_id = ?",
                    (dataset["dataset_id"],),
                ).fetchone()[0]
            manifest = dataset_service.get_manifest(dataset["dataset_id"])
            if event_count < manifest["event_count"]:
                ingestion_service.import_file(
                    dataset["dataset_id"],
                    dataset_service.get_event_file_path(dataset["dataset_id"]),
                )
        yield

    app = FastAPI(title="Security Operations Platform", version="0.1.0", lifespan=lifespan)

    @app.get("/api/datasets")
    def list_datasets():
        return {"datasets": [dashboard_data.dataset_detail(item["dataset_id"]) for item in dataset_service.list_datasets()]}

    @app.get("/api/datasets/{dataset_id}")
    def get_dataset(dataset_id: str):
        try:
            return dashboard_data.dataset_detail(dataset_id)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None

    @app.get("/api/datasets/{dataset_id}/events")
    def search_events(
        dataset_id: str,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
        severity: str | None = None,
        category: str | None = None,
        q: str | None = None,
    ):
        try:
            return event_service.search(dataset_id, limit=limit, offset=offset, severity=severity, category=category, query=q)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None

    @app.post("/api/datasets/{dataset_id}/ingestions", status_code=201)
    async def import_events(
        dataset_id: str,
        request: Request,
        filename: Annotated[str, Query(min_length=1, max_length=255)],
    ):
        try:
            dataset_service.require_dataset(dataset_id)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None
        suffix = Path(filename).suffix.lower()
        if suffix not in {".jsonl", ".json", ".csv"}:
            raise HTTPException(status_code=415, detail="Supported formats are JSONL, JSON, and CSV")

        staging_dir.mkdir(parents=True, exist_ok=True)
        staged_path = staging_dir / f"{uuid.uuid4()}{suffix}"
        size = 0
        try:
            with staged_path.open("wb") as stream:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > MAX_FILE_BYTES:
                        raise HTTPException(status_code=413, detail="Upload exceeds 100 MiB limit")
                    stream.write(chunk)
            return ingestion_service.import_file(dataset_id, staged_path, source_name=Path(filename).name)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        finally:
            staged_path.unlink(missing_ok=True)

    @app.post("/api/datasets/{dataset_id}/investigations", status_code=201)
    def start_investigation(dataset_id: str, request: InvestigationRequest):
        try:
            return investigation_service.start(dataset_id, request.requested_by)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None

    @app.post("/api/investigations/{investigation_id}/run")
    def run_investigation(investigation_id: str):
        try:
            return orchestrator.run(investigation_id)
        except InvestigationNotFoundError:
            raise HTTPException(status_code=404, detail="Investigation not found") from None
        except InvestigationStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/proposals/{proposal_id}")
    def get_proposal(proposal_id: str):
        try:
            return proposal_review_service.evaluate(proposal_id)
        except ProposalNotFoundError:
            raise HTTPException(status_code=404, detail="Proposal not found") from None

    @app.get("/api/proposals/{proposal_id}/approvals")
    def get_proposal_approvals(proposal_id: str):
        try:
            return {"proposal_id": proposal_id, "approvals": proposal_review_service.history(proposal_id)}
        except ProposalNotFoundError:
            raise HTTPException(status_code=404, detail="Proposal not found") from None

    @app.post("/api/proposals/{proposal_id}/decisions")
    def decide_proposal(proposal_id: str, request: ProposalDecisionRequest):
        try:
            return proposal_review_service.decide(
                proposal_id,
                reviewer=request.reviewer,
                decision=request.decision,
                comment=request.comment,
                action_type=request.action_type,
                target_type=request.target_type,
                target_value=request.target_value,
            )
        except ProposalNotFoundError:
            raise HTTPException(status_code=404, detail="Proposal not found") from None
        except ProposalDecisionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except PolicyRejectedError as exc:
            raise HTTPException(status_code=422, detail={"code": exc.result.code, "reason": exc.result.reason}) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/proposals/{proposal_id}/executions", status_code=201)
    def execute_proposal(
        proposal_id: str,
        request: ExecutionRequest,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=128)],
    ):
        try:
            return remediation_worker.execute(proposal_id, request.approval_id, idempotency_key)
        except ExecutionNotAuthorized as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ExecutionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ProposalNotFoundError:
            raise HTTPException(status_code=404, detail="Proposal not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/executions/{execution_id}")
    def get_execution(execution_id: str):
        try:
            return remediation_worker.get_execution(execution_id)
        except ExecutionNotFoundError:
            raise HTTPException(status_code=404, detail="Execution not found") from None

    @app.get("/api/executions/{execution_id}/comparison")
    def compare_execution(execution_id: str):
        try:
            return remediation_worker.comparison(execution_id)
        except ExecutionNotFoundError:
            raise HTTPException(status_code=404, detail="Execution not found") from None

    @app.get("/api/overview")
    def get_overview(dataset_id: str | None = None):
        try:
            return dashboard_data.overview(dataset_id)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None

    @app.get("/api/investigations")
    def list_investigations(
        dataset_id: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        try:
            return dashboard_data.investigations(dataset_id=dataset_id, limit=limit, offset=offset)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None

    @app.get("/api/findings")
    def list_findings(
        dataset_id: str | None = None,
        investigation_id: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        try:
            return dashboard_data.findings(dataset_id=dataset_id, investigation_id=investigation_id, limit=limit, offset=offset)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None

    @app.get("/api/proposals")
    def list_proposals(
        dataset_id: str | None = None,
        status: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        try:
            return dashboard_data.proposals(dataset_id=dataset_id, status=status, limit=limit, offset=offset)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None

    @app.get("/api/processed-events")
    def list_processed_events(
        dataset_id: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        try:
            return dashboard_data.processed_events(dataset_id=dataset_id, limit=limit, offset=offset)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None

    @app.get("/api/audit")
    def list_audit_history(
        dataset_id: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        try:
            return dashboard_data.audit_history(dataset_id=dataset_id, limit=limit, offset=offset)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None

    @app.get("/api/reports/summary")
    def report_summary(dataset_id: str | None = None):
        try:
            return dashboard_data.reports(dataset_id)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None

    @app.get("/api/reports/export")
    def export_report(format: Literal["json", "csv"] = "json", dataset_id: str | None = None):
        try:
            report = dashboard_data.reports(dataset_id)
        except DatasetNotFoundError:
            raise HTTPException(status_code=404, detail="Dataset not found") from None
        if format == "json":
            payload = json.dumps(report, indent=2, sort_keys=True)
            return StreamingResponse(iter([payload]), media_type="application/json",
                                     headers={"Content-Disposition": "attachment; filename=security-report.json"})
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(("section", "name", "value"))
        for key in ("dataset_id", "generated_at"):
            writer.writerow(("report", key, report.get(key)))
        for key, value in report["overview"].items():
            if isinstance(value, (str, int, float)) or value is None:
                writer.writerow(("overview", key, value))
            elif isinstance(value, list):
                for row in value:
                    writer.writerow((key, row.get("label", row.get("period", "")), row.get("count", "")))
            elif isinstance(value, dict):
                for name, count in value.items():
                    writer.writerow((key, name, count))
        for row in report["agent_performance"]:
            writer.writerow(("agent_performance", row["agent_name"], json.dumps(row)))
        for row in report["remediation_executions"]:
            writer.writerow(("remediation_executions", row["label"], row["count"]))
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                                 headers={"Content-Disposition": "attachment; filename=security-report.csv"})

    @app.get("/api/settings")
    def get_settings_summary():
        return dashboard_data.settings_summary()

    dashboard_directory = Path(__file__).resolve().parents[1] / "dashboard"
    app.mount("/", StaticFiles(directory=dashboard_directory, html=True), name="dashboard")

    return app


app = create_app()
