"""
TinyGuardian Main Class
Orchestrates IoT monitoring, LLM analysis, and threat detection.
"""

import paho.mqtt.client as mqtt
from typing import Dict, Optional, Callable
from datetime import datetime
import json
import re
from loguru import logger
import threading
import queue

from .llm_client import LLMClient
from .threat_classifier import ThreatClassifier, SecurityEvent


class TinyGuardian:
    """
    Main TinyGuardian agent that monitors IoT devices and detects threats.
    """
    
    def __init__(self,
                 mqtt_broker: str = "localhost",
                 mqtt_port: int = 1883,
                 mqtt_topics: list = None,
                 llm_provider: str = "ollama",
                 llm_model: str = "phi3:mini",
                 llm_base_url: str = "http://localhost:11434",
                 severity_threshold: float = 0.7):
        """
        Initialize TinyGuardian.
        
        Args:
            mqtt_broker: MQTT broker hostname
            mqtt_port: MQTT broker port
            mqtt_topics: List of MQTT topics to subscribe to
            llm_provider: LLM provider name
            llm_model: LLM model name
            llm_base_url: LLM API base URL
            severity_threshold: Minimum severity for alerts
        """
        self.mqtt_broker = mqtt_broker
        self.mqtt_port = mqtt_port
        self.mqtt_topics = mqtt_topics or ["iot/devices/+/logs"]
        
        # Initialize components
        self.llm_client = LLMClient(
            provider=llm_provider,
            model=llm_model,
            base_url=llm_base_url
        )
        self.classifier = ThreatClassifier(severity_threshold=severity_threshold)
        
        # MQTT client
        self.mqtt_client = None
        self.running = False
        
        # Event storage
        self.events: list = []
        self.alert_callbacks: list = []
        
        # Processing queue
        self.processing_queue = queue.Queue()
        self.processing_thread = None
        
        logger.info("TinyGuardian initialized")
    
    def start_monitoring(self):
        """Start monitoring IoT devices."""
        if self.running:
            logger.warning("Already monitoring")
            return
        
        # Test LLM connection
        if not self.llm_client.test_connection():
            logger.error("Failed to connect to LLM provider")
            raise ConnectionError("LLM provider not available")
        
        # Setup MQTT
        self.mqtt_client = mqtt.Client(client_id="tinyguardian")
        self.mqtt_client.on_connect = self._on_mqtt_connect
        self.mqtt_client.on_message = self._on_mqtt_message
        
        try:
            self.mqtt_client.connect(self.mqtt_broker, self.mqtt_port, 60)
        except Exception as e:
            logger.error(f"Failed to connect to MQTT broker: {e}")
            raise
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.processing_thread.start()
        
        # Start MQTT loop
        self.running = True
        self.mqtt_client.loop_start()
        
        logger.info("Started monitoring IoT devices")
    
    def stop_monitoring(self):
        """Stop monitoring."""
        self.running = False
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        logger.info("Stopped monitoring")
    
    def _on_mqtt_connect(self, client, userdata, flags, rc):
        """Callback for MQTT connection."""
        if rc == 0:
            logger.info("Connected to MQTT broker")
            # Subscribe to topics
            for topic in self.mqtt_topics:
                client.subscribe(topic)
                logger.info(f"Subscribed to {topic}")
        else:
            logger.error(f"Failed to connect to MQTT broker: {rc}")
    
    def _on_mqtt_message(self, client, userdata, msg):
        """Callback for MQTT messages."""
        try:
            payload = msg.payload.decode('utf-8')
            topic = msg.topic
            
            # Extract device ID from topic (e.g., iot/devices/device_01/logs -> device_01)
            device_match = re.search(r'devices/([^/]+)', topic)
            device_id = device_match.group(1) if device_match else "unknown"
            
            # Add to processing queue
            self.processing_queue.put({
                "device_id": device_id,
                "log_message": payload,
                "topic": topic,
                "timestamp": datetime.now()
            })
        except Exception as e:
            logger.error(f"Error processing MQTT message: {e}")
    
    def _process_queue(self):
        """Process log messages from queue."""
        while self.running:
            try:
                item = self.processing_queue.get(timeout=1)
                self._process_log(item)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing queue item: {e}")
    
    def _process_log(self, item: Dict):
        """Process a single log message."""
        device_id = item["device_id"]
        log_message = item["log_message"]
        timestamp = item["timestamp"]
        
        logger.debug(f"Processing log from {device_id}: {log_message[:100]}")
        
        # Analyze with LLM
        llm_analysis = self.llm_client.analyze_log(log_message, device_id)
        
        # Classify threat
        event = self.classifier.classify(
            device_id=device_id,
            log_message=log_message,
            llm_analysis=llm_analysis,
            timestamp=timestamp
        )
        
        # Store event
        self.events.append(event)
        
        # Check if alert needed
        if self.classifier.is_alert(event):
            logger.warning(f"🚨 ALERT: {event.threat_type.value} on {device_id} (severity: {event.severity:.2f})")
            self._trigger_alert(event)
    
    def _trigger_alert(self, event: SecurityEvent):
        """Trigger alert callbacks."""
        for callback in self.alert_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def register_alert_callback(self, callback: Callable[[SecurityEvent], None]):
        """Register callback for alerts."""
        self.alert_callbacks.append(callback)
    
    def get_recent_events(self, limit: int = 100) -> list:
        """Get recent security events."""
        return sorted(self.events, key=lambda e: e.timestamp, reverse=True)[:limit]
    
    def get_alerts(self, limit: int = 50) -> list:
        """Get recent alerts (high severity events)."""
        alerts = [e for e in self.events if self.classifier.is_alert(e)]
        return sorted(alerts, key=lambda e: e.timestamp, reverse=True)[:limit]
    
    def get_stats(self) -> Dict:
        """Get statistics."""
        total_events = len(self.events)
        alerts = len([e for e in self.events if self.classifier.is_alert(e)])
        
        threat_types = {}
        for event in self.events:
            threat_type = event.threat_type.value
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        return {
            "total_events": total_events,
            "alerts": alerts,
            "threat_types": threat_types,
            "uptime_seconds": (datetime.now() - self.events[0].timestamp).total_seconds() if self.events else 0
        }

