"""
SIEM Backend API
FastAPI-based REST API and WebSocket server for SIEM dashboard
"""

from fastapi import FastAPI, WebSocket, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Optional, Set
import uvicorn
from pydantic import BaseModel

from detection_engine import (
    DetectionEngine,
    SecurityEvent,
    EventType,
    SeverityLevel,
    Alert,
)


# ============================================================================
# Data Models for API
# ============================================================================


class EventCreateRequest(BaseModel):
    """Request to create a new security event"""

    timestamp: str  # ISO format
    source: str
    event_type: str
    severity: str
    user: Optional[str] = None
    host: Optional[str] = None
    ip_address: Optional[str] = None
    details: dict = {}
    raw_log: str = ""


class AlertResponse(BaseModel):
    """Alert response model"""

    id: str
    timestamp: str
    severity: str
    title: str
    description: str
    rule_name: str
    event_count: int
    status: str
    assigned_to: Optional[str] = None


class AlertAckRequest(BaseModel):
    """Request to acknowledge an alert"""

    assigned_to: Optional[str] = None


class EventSearchRequest(BaseModel):
    """Advanced event search"""

    query: str
    source: Optional[str] = None
    severity: Optional[str] = None
    event_type: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    ip_address: Optional[str] = None
    limit: int = 100


# ============================================================================
# FastAPI Application
# ============================================================================


app = FastAPI(
    title="Enterprise SIEM",
    description="Security Information & Event Management System",
    version="1.0.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
detection_engine = DetectionEngine()
active_connections: Set[WebSocket] = set()


# ============================================================================
# WebSocket for Real-time Updates
# ============================================================================


@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time event stream"""
    await websocket.accept()
    active_connections.add(websocket)

    try:
        while True:
            # Send heartbeat every 30 seconds
            await asyncio.sleep(30)
            await websocket.send_json(
                {"type": "heartbeat", "timestamp": datetime.now().isoformat()}
            )
    except Exception:
        active_connections.discard(websocket)


async def broadcast_alert(alert: Alert):
    """Broadcast alert to all connected WebSocket clients"""
    message = {
        "type": "alert",
        "data": alert.to_dict(),
    }
    disconnected = set()
    for connection in active_connections:
        try:
            await connection.send_json(message)
        except Exception:
            disconnected.add(connection)

    active_connections.difference_update(disconnected)


async def broadcast_event(event: SecurityEvent):
    """Broadcast event to all connected WebSocket clients"""
    message = {
        "type": "event",
        "data": event.to_dict(),
    }
    disconnected = set()
    for connection in active_connections:
        try:
            await connection.send_json(message)
        except Exception:
            disconnected.add(connection)

    active_connections.difference_update(disconnected)


# ============================================================================
# REST API Endpoints
# ============================================================================


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/api/events")
async def create_event(event_request: EventCreateRequest):
    """
    Ingest a security event from external source.

    Sources: Windows Event Log, Firewall, IDS/IPS, Web Server, etc.
    """
    try:
        timestamp = datetime.fromisoformat(event_request.timestamp)
    except ValueError:
        timestamp = datetime.now()

    try:
        event_type = EventType[event_request.event_type.upper()]
    except KeyError:
        event_type = EventType.UNUSUAL_ACTIVITY

    try:
        severity = SeverityLevel[event_request.severity.upper()]
    except KeyError:
        severity = SeverityLevel.MEDIUM

    event = SecurityEvent(
        timestamp=timestamp,
        source=event_request.source,
        event_type=event_type,
        severity=severity,
        user=event_request.user,
        host=event_request.host,
        ip_address=event_request.ip_address,
        details=event_request.details,
        raw_log=event_request.raw_log,
    )

    # Process event through detection engine
    alerts = detection_engine.process_event(event)

    # Broadcast to WebSocket clients
    await broadcast_event(event)
    for alert in alerts:
        await broadcast_alert(alert)

    return {
        "status": "success",
        "event_id": f"{event.source}_{int(timestamp.timestamp())}",
        "alerts_generated": len(alerts),
    }


@app.get("/api/alerts", response_model=List[AlertResponse])
async def get_alerts(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
):
    """Get security alerts with optional filtering"""
    severity_obj = None
    if severity:
        try:
            severity_obj = SeverityLevel[severity.upper()]
        except KeyError:
            pass

    alerts = detection_engine.get_alerts(
        status=status, severity=severity_obj, limit=limit
    )
    return [
        AlertResponse(
            id=a.id,
            timestamp=a.timestamp.isoformat(),
            severity=a.severity.name,
            title=a.title,
            description=a.description,
            rule_name=a.rule_name,
            event_count=len(a.events),
            status=a.status,
            assigned_to=a.assigned_to,
        )
        for a in alerts
    ]


@app.get("/api/alerts/{alert_id}")
async def get_alert_details(alert_id: str):
    """Get detailed alert information including related events"""
    for alert in detection_engine.alerts:
        if alert.id == alert_id:
            return {
                "alert": alert.to_dict(),
                "events": [e.to_dict() for e in alert.events],
                "timeline": sorted(
                    [e.timestamp.isoformat() for e in alert.events]
                ),
            }
    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, request: AlertAckRequest):
    """Mark alert as acknowledged"""
    for alert in detection_engine.alerts:
        if alert.id == alert_id:
            detection_engine.acknowledge_alert(alert_id, request.assigned_to)
            return {"status": "success", "alert_id": alert_id}
    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    """Mark alert as resolved"""
    for alert in detection_engine.alerts:
        if alert.id == alert_id:
            detection_engine.resolve_alert(alert_id)
            return {"status": "success", "alert_id": alert_id}
    raise HTTPException(status_code=404, detail="Alert not found")


@app.get("/api/stats")
async def get_statistics():
    """Get overall SIEM statistics"""
    stats = detection_engine.get_alert_stats()
    return {
        **stats,
        "timestamp": datetime.now().isoformat(),
        "active_rules": len(detection_engine.rules),
        "connected_clients": len(active_connections),
    }


@app.post("/api/events/search")
async def search_events(search: EventSearchRequest):
    """Full-text search on security events"""
    results = []

    for event in reversed(detection_engine.event_history[-1000:]):
        # Filter by criteria
        if search.source and event.source != search.source:
            continue
        if search.user and event.user != search.user:
            continue
        if search.host and event.host != search.host:
            continue
        if search.ip_address and event.ip_address != search.ip_address:
            continue
        if search.event_type and event.event_type.value != search.event_type:
            continue
        if search.severity and event.severity.name != search.severity:
            continue

        # Simple keyword search in raw log
        if search.query.lower() not in event.raw_log.lower():
            continue

        results.append(event.to_dict())

        if len(results) >= search.limit:
            break

    return {
        "query": search.query,
        "results_count": len(results),
        "results": results,
    }


@app.get("/api/sources")
async def get_event_sources():
    """Get list of event sources"""
    sources = set(e.source for e in detection_engine.event_history)
    return {
        "sources": sorted(list(sources)),
        "total": len(sources),
    }


@app.get("/api/users")
async def get_active_users():
    """Get list of users with events"""
    users = set(e.user for e in detection_engine.event_history if e.user)
    return {
        "users": sorted(list(users)),
        "total": len(users),
    }


@app.get("/api/hosts")
async def get_monitored_hosts():
    """Get list of monitored hosts"""
    hosts = set(e.host for e in detection_engine.event_history if e.host)
    return {
        "hosts": sorted(list(hosts)),
        "total": len(hosts),
    }


@app.get("/api/timeline")
async def get_event_timeline(hours: int = Query(24, ge=1, le=168)):
    """Get event timeline for last N hours"""
    cutoff = datetime.now() - timedelta(hours=hours)
    events = [e for e in detection_engine.event_history if e.timestamp > cutoff]

    # Aggregate by hour
    timeline = {}
    for event in events:
        hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
        if hour_key not in timeline:
            timeline[hour_key] = {
                "count": 0,
                "by_severity": {s.name: 0 for s in SeverityLevel},
            }
        timeline[hour_key]["count"] += 1
        timeline[hour_key]["by_severity"][event.severity.name] += 1

    return {
        "hours": hours,
        "timeline": timeline,
    }


@app.get("/api/threat-intelligence")
async def get_threat_intel():
    """Get threat intelligence summary"""
    # Top IPs with failed logins
    ip_failures = {}
    for e in detection_engine.event_history:
        if e.event_type == EventType.FAILED_LOGIN and e.ip_address:
            ip_failures[e.ip_address] = ip_failures.get(e.ip_address, 0) + 1

    # Top users with security events
    user_events = {}
    for e in detection_engine.event_history:
        if e.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL] and e.user:
            user_events[e.user] = user_events.get(e.user, 0) + 1

    return {
        "top_malicious_ips": sorted(
            ip_failures.items(), key=lambda x: x[1], reverse=True
        )[:10],
        "risky_users": sorted(
            user_events.items(), key=lambda x: x[1], reverse=True
        )[:10],
        "alert_rate_last_hour": len(
            [
                a
                for a in detection_engine.alerts
                if a.timestamp > datetime.now() - timedelta(hours=1)
            ]
        ),
    }


# ============================================================================
# Sample Data Generator (for demo)
# ============================================================================


async def generate_sample_events():
    """Generate sample security events for demo purposes"""
    import random

    users = ["alice", "bob", "charlie", "diana", "eve"]
    sources = ["Windows Event Log", "Firewall", "IDS", "Web Server", "DNS"]
    hosts = ["ws-001", "ws-002", "srv-db-01", "srv-web-01", "srv-web-02"]
    ips = [
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.102",
        "10.0.0.50",
        "203.0.113.42",
    ]

    while True:
        await asyncio.sleep(random.randint(2, 8))

        event_type = random.choice(list(EventType))
        severity = random.choice(list(SeverityLevel))

        event = SecurityEvent(
            timestamp=datetime.now(),
            source=random.choice(sources),
            event_type=event_type,
            severity=severity,
            user=random.choice(users) if random.random() > 0.2 else None,
            host=random.choice(hosts),
            ip_address=random.choice(ips),
            details={
                "duration_ms": random.randint(100, 5000),
                "bytes_transferred": random.randint(1000, 1000000),
            },
            raw_log=f"[{datetime.now().isoformat()}] {event_type.value}: event detected",
        )

        alerts = detection_engine.process_event(event)
        await broadcast_event(event)
        for alert in alerts:
            await broadcast_alert(alert)


# ============================================================================
# Startup/Shutdown
# ============================================================================


@app.on_event("startup")
async def startup_event():
    """Start background tasks"""
    asyncio.create_task(generate_sample_events())


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
