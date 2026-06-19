"""
logs.py — Receives frontend console logs and errors, prints them to stdout
so they show up in Railway logs alongside backend logs.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
import logging

router = APIRouter()
logger = logging.getLogger("frontend")


class LogEntry(BaseModel):
    level: str
    message: str
    timestamp: Optional[str] = None


class LogBatch(BaseModel):
    logs: List[LogEntry]
    userId: Optional[str] = None


@router.post("/frontend")
def receive_frontend_logs(batch: LogBatch):
    for entry in batch.logs:
        line = f"[FRONTEND][{entry.level.upper()}] user={batch.userId} ts={entry.timestamp} {entry.message}"
        print(line, flush=True)  # Railway captures stdout directly
    return {"received": len(batch.logs)}