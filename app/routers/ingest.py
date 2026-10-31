"""
CYBERSICKER — Production Network Traffic Ingestion Router
Supports real-time ingestion of .pcap, .pcapng, and .csv files.
Reconstructs bidirectional network flows, extracts NSL-KDD statistical features,
and runs live autoencoder inference with zero hardcoded file dependencies.
"""

from __future__ import annotations

import io
import time
import logging
from typing import Optional, Dict, Any, List, Union
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Request, status
from pydantic import BaseModel, Field
import pandas as pd
import numpy as np

from app.services.pcap_extractor import parse_pcap_to_flows, extract_kdd_features_from_flows, KDD_NUMERICAL_FEATURES
from app.services.traffic_scanner import traffic_scanner_service, DEFAULT_THRESHOLD
from app.services.telemetry import telemetry_service

logger = logging.getLogger("Cybersicker.IngestRouter")

router = APIRouter(prefix="/api/v1", tags=["Traffic Ingestion & Autoencoder Inference"])


class TrafficScanResponse(BaseModel):
    success: bool
    data: Dict[str, Any]


@router.post("/scan/traffic")
async def scan_network_traffic(
    request: Request,
    file: Optional[UploadFile] = File(None),
    threshold: Optional[float] = Form(DEFAULT_THRESHOLD)
):
    """
    Accepts raw packet captures (.pcap, .pcapng) or structured tabular logs (.csv).
    Parses flows, extracts 41 statistical features, and computes autoencoder MSE reconstruction loss.
    """
    thresh = float(threshold or DEFAULT_THRESHOLD)
    start_time = time.time()

    # 1. Handle Multipart File Upload
    if file is not None:
        filename = (file.filename or "upload.pcap").lower()
        content = await file.read()
        if not content:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")

        # PCAP / PCAPNG Processing
        if filename.endswith(".pcap") or filename.endswith(".pcapng"):
            logger.info("Ingesting PCAP file: %s (%d bytes)", filename, len(content))
            try:
                flows = parse_pcap_to_flows(content)
                if not flows:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="No IP/TCP/UDP packets found in uploaded PCAP file."
                    )

                df, endpoint_meta = extract_kdd_features_from_flows(flows)
                total_flows = len(df)

                # Execute in-memory autoencoder inference
                scan_report = traffic_scanner_service.process_dataframe(
                    df=df,
                    anomaly_threshold=thresh,
                    source_name=filename
                )

                # Align endpoint metadata with anomaly scores
                top_indices = scan_report.get("top_anomaly_indices", [])
                top_endpoints = []
                for idx in top_indices:
                    if idx < len(endpoint_meta):
                        ep = endpoint_meta[idx]
                        score = scan_report["top_anomaly_scores"][top_indices.index(idx)] if "top_anomaly_scores" in scan_report else 0.0
                        top_endpoints.append({
                            **ep,
                            "mse": score,
                            "anomaly_flag": score > thresh
                        })

                # Compile final response report
                scan_report["file_type"] = "pcap"
                scan_report["total_flows"] = total_flows
                scan_report["top_anomalous_endpoints"] = top_endpoints
                scan_report["highest_reconstruction_loss_contributors"] = scan_report.get("high_risk_dimensions", [])

                # Emit specific PCAP_FLOW_PROCESSED telemetry contract event
                telemetry_service.emit({
                    "event": "PCAP_FLOW_PROCESSED",
                    "flows": total_flows,
                    "anomalies": scan_report.get("anomalies_detected", 0),
                    "filename": filename,
                    "latency_ms": int((time.time() - start_time) * 1000)
                })

                return {"success": True, "data": scan_report}

            except HTTPException:
                raise
            except Exception as e:
                logger.error("PCAP parsing failed: %s", e, exc_info=True)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"PCAP Flow Extraction Failed: {str(e)}"
                )

        # CSV / Tabular Processing
        elif filename.endswith(".csv") or filename.endswith(".txt"):
            logger.info("Ingesting CSV file: %s (%d bytes)", filename, len(content))
            try:
                scan_report = traffic_scanner_service.scan_csv_bytes(
                    file_bytes=content,
                    filename=filename,
                    threshold=thresh
                )
                scan_report["file_type"] = "csv"
                scan_report["total_flows"] = scan_report.get("total_records", 0)
                scan_report["highest_reconstruction_loss_contributors"] = scan_report.get("high_risk_dimensions", [])

                telemetry_service.emit({
                    "event": "PCAP_FLOW_PROCESSED",
                    "flows": scan_report.get("total_records", 0),
                    "anomalies": scan_report.get("anomalies_detected", 0),
                    "filename": filename,
                    "latency_ms": int((time.time() - start_time) * 1000)
                })

                return {"success": True, "data": scan_report}
            except Exception as e:
                logger.error("CSV scanning failed: %s", e)
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file format '{filename}'. Allowed formats: .pcap, .pcapng, .csv, .txt"
            )

    # 2. Handle JSON Body (raw_csv or records matrix)
    try:
        body = await request.json()
        raw_csv = body.get("raw_csv")
        records = body.get("records")
        thresh = float(body.get("threshold", thresh))

        if raw_csv:
            scan_report = traffic_scanner_service.scan_csv_bytes(
                file_bytes=raw_csv.encode("utf-8"),
                filename="stream_payload.csv",
                threshold=thresh
            )
            scan_report["file_type"] = "raw_csv"
            scan_report["total_flows"] = scan_report.get("total_records", 0)
            scan_report["highest_reconstruction_loss_contributors"] = scan_report.get("high_risk_dimensions", [])

            telemetry_service.emit({
                "event": "PCAP_FLOW_PROCESSED",
                "flows": scan_report.get("total_records", 0),
                "anomalies": scan_report.get("anomalies_detected", 0),
                "filename": "stream_payload.csv",
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            return {"success": True, "data": scan_report}

        if records and isinstance(records, list):
            scan_report = traffic_scanner_service.scan_records(
                records=records,
                threshold=thresh,
                source_name="stream_matrix"
            )
            scan_report["file_type"] = "matrix"
            scan_report["total_flows"] = scan_report.get("total_records", 0)
            scan_report["highest_reconstruction_loss_contributors"] = scan_report.get("high_risk_dimensions", [])

            telemetry_service.emit({
                "event": "PCAP_FLOW_PROCESSED",
                "flows": scan_report.get("total_records", 0),
                "anomalies": scan_report.get("anomalies_detected", 0),
                "filename": "stream_matrix",
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            return {"success": True, "data": scan_report}

    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="No network traffic data provided. Upload a .pcap/.csv file or supply 'raw_csv'/'records' in JSON."
    )
