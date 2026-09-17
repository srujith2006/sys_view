"""
Native Desktop Notification Engine for QE-NIDS Endpoint Agent.
Sends native Windows Toast Notifications with rate limiting and severity icons.
"""

import time
from typing import Dict, Any, Optional

try:
    from win11toast import toast
    HAS_WIN11TOAST = True
except ImportError:
    HAS_WIN11TOAST = False

class DesktopNotifier:
    """
    Manages native OS notifications with rate limiting to prevent alert fatigue.
    """
    def __init__(self, cooldown_seconds: float = 10.0):
        self.cooldown_seconds = cooldown_seconds
        self.last_notified: Dict[str, float] = {}

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "HIGH",
        category: str = "Threat",
        on_click_url: Optional[str] = None
    ) -> bool:
        """
        Send a native desktop notification if not within cooldown period.
        """
        now = time.time()
        cooldown_key = f"{severity}_{category}"
        last_time = self.last_notified.get(cooldown_key, 0.0)
        
        # Rate limit to avoid spamming the user
        if now - last_time < self.cooldown_seconds:
            return False
            
        self.last_notified[cooldown_key] = now
        
        # Severity emoji / sound
        icons = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "🔔",
            "LOW": "ℹ️",
            "SAFE": "🛡️"
        }
        icon = icons.get(severity.upper(), "🛡️")
        formatted_title = f"{icon} QE-NIDS: {title}"
        
        if HAS_WIN11TOAST:
            try:
                toast(
                    formatted_title,
                    message,
                    duration="short",
                    on_click=on_click_url
                )
                return True
            except Exception:
                pass
                
        print(f"\n[{severity}] {formatted_title}: {message}")
        return True

    def notify_threat(self, alert: Dict[str, Any], dashboard_url: str = "http://localhost:8501") -> bool:
        """Helper to trigger notification from a fusion alert dictionary."""
        severity = alert.get("severity", "LOW")
        if severity not in ["MEDIUM", "HIGH", "CRITICAL"] and not alert.get("is_novel_anomaly"):
            return False
            
        category = alert.get("attack_category", "Anomalous Traffic")
        risk = alert.get("risk_score", 0.0)
        meta = alert.get("metadata", {})
        src_ip = meta.get("Source IP", "Remote Host")
        dst_port = meta.get("Destination Port", "Service")
        
        if alert.get("is_novel_anomaly"):
            title = "Potential Novel Anomaly Detected!"
            msg = f"Zero-Day network telemetry pattern from {src_ip} (Risk: {risk:.0f}/100). Click to inspect."
        else:
            title = f"{category} Detected!"
            msg = f"Suspicious activity targeted at port {dst_port} from {src_ip} (Risk: {risk:.0f}/100)."
            
        return self.send_alert(
            title=title,
            message=msg,
            severity=severity,
            category=category,
            on_click_url=dashboard_url
        )
