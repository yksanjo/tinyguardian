"""
TinyGuardian FastAPI Application
Web API and dashboard for monitoring.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uvicorn
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinyguardian.core.guardian import TinyGuardian
from tinyguardian.core.threat_classifier import SecurityEvent

app = FastAPI(title="TinyGuardian API", version="0.1.0")

# Initialize guardian (will be started separately)
guardian_instance: Optional[TinyGuardian] = None


def set_guardian(guardian: TinyGuardian):
    """Set the guardian instance."""
    global guardian_instance
    guardian_instance = guardian


class EventResponse(BaseModel):
    """Event response model."""
    event_id: str
    device_id: str
    timestamp: str
    threat_level: str
    severity: float
    threat_type: str
    explanation: str
    recommendation: str
    source_ip: Optional[str] = None
    user: Optional[str] = None


@app.get("/")
async def root():
    """Root endpoint - serve dashboard."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>TinyGuardian Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
            .stats { display: flex; gap: 20px; margin: 20px 0; }
            .stat-card { background: white; padding: 20px; border-radius: 5px; flex: 1; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
            .alerts { background: white; padding: 20px; border-radius: 5px; margin-top: 20px; }
            .alert { padding: 15px; margin: 10px 0; border-left: 4px solid #e74c3c; background: #fff5f5; }
            .alert.medium { border-left-color: #f39c12; }
            .alert.low { border-left-color: #3498db; }
            .alert-header { font-weight: bold; margin-bottom: 5px; }
            .refresh-btn { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🤖 TinyGuardian Dashboard</h1>
                <p>On-Device LLM + IoT Security Agent</p>
            </div>
            <div class="stats" id="stats">
                <div class="stat-card">
                    <div class="stat-label">Total Events</div>
                    <div class="stat-value" id="total-events">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Alerts</div>
                    <div class="stat-value" id="alerts">-</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Threat Types</div>
                    <div class="stat-value" id="threat-types">-</div>
                </div>
            </div>
            <div class="alerts">
                <h2>Recent Alerts</h2>
                <button class="refresh-btn" onclick="loadData()">Refresh</button>
                <div id="alerts-list">Loading...</div>
            </div>
        </div>
        <script>
            async function loadData() {
                const stats = await fetch('/api/v1/stats').then(r => r.json());
                document.getElementById('total-events').textContent = stats.total_events || 0;
                document.getElementById('alerts').textContent = stats.alerts || 0;
                document.getElementById('threat-types').textContent = Object.keys(stats.threat_types || {}).length;
                
                const alerts = await fetch('/api/v1/alerts').then(r => r.json());
                const alertsList = document.getElementById('alerts-list');
                if (alerts.length === 0) {
                    alertsList.innerHTML = '<p>No alerts</p>';
                } else {
                    alertsList.innerHTML = alerts.map(a => `
                        <div class="alert ${a.threat_level}">
                            <div class="alert-header">${a.threat_type} - ${a.device_id} (${a.severity.toFixed(2)})</div>
                            <div>${a.explanation}</div>
                            <div style="margin-top: 10px; font-size: 0.9em; color: #666;">${a.recommendation}</div>
                        </div>
                    `).join('');
                }
            }
            loadData();
            setInterval(loadData, 5000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/api/v1/alerts")
async def get_alerts(limit: int = 50):
    """Get recent alerts."""
    if not guardian_instance:
        return []
    
    alerts = guardian_instance.get_alerts(limit=limit)
    return [EventResponse(
        event_id=e.event_id,
        device_id=e.device_id,
        timestamp=e.timestamp.isoformat(),
        threat_level=e.threat_level,
        severity=e.severity,
        threat_type=e.threat_type.value,
        explanation=e.explanation,
        recommendation=e.recommendation,
        source_ip=e.source_ip,
        user=e.user
    ).dict() for e in alerts]


@app.get("/api/v1/events")
async def get_events(limit: int = 100):
    """Get recent events."""
    if not guardian_instance:
        return []
    
    events = guardian_instance.get_recent_events(limit=limit)
    return [EventResponse(
        event_id=e.event_id,
        device_id=e.device_id,
        timestamp=e.timestamp.isoformat(),
        threat_level=e.threat_level,
        severity=e.severity,
        threat_type=e.threat_type.value,
        explanation=e.explanation,
        recommendation=e.recommendation,
        source_ip=e.source_ip,
        user=e.user
    ).dict() for e in events]


@app.get("/api/v1/stats")
async def get_stats():
    """Get statistics."""
    if not guardian_instance:
        return {"total_events": 0, "alerts": 0, "threat_types": {}}
    
    return guardian_instance.get_stats()


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy", "monitoring": guardian_instance is not None and guardian_instance.running}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)




