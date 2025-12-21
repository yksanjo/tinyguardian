"""
TinyGuardian Main Entry Point
"""

import argparse
import yaml
from pathlib import Path
from loguru import logger
import signal
import sys

from tinyguardian.core.guardian import TinyGuardian
from api.main import app, set_guardian
import uvicorn
import threading


def load_config(config_path: str = "config/config.yaml") -> dict:
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="TinyGuardian IoT Security Agent")
    parser.add_argument("--config", type=str, default="config/config.yaml", help="Config file path")
    parser.add_argument("--log-level", type=str, default="INFO", help="Log level")
    
    args = parser.parse_args()
    
    # Setup logging
    logger.remove()
    logger.add(sys.stderr, level=args.log_level)
    
    # Load config
    config = load_config(args.config)
    
    # Initialize guardian
    guardian = TinyGuardian(
        mqtt_broker=config["mqtt"]["broker"],
        mqtt_port=config["mqtt"]["port"],
        mqtt_topics=config["mqtt"]["topics"],
        llm_provider=config["llm"]["provider"],
        llm_model=config["llm"]["model"],
        llm_base_url=config["llm"]["base_url"],
        severity_threshold=config["threat_detection"]["severity_threshold"]
    )
    
    # Set guardian for API
    set_guardian(guardian)
    
    # Register alert callback
    def on_alert(event):
        logger.warning(f"🚨 ALERT: {event.threat_type.value} on {event.device_id}")
        logger.warning(f"   Severity: {event.severity:.2f}")
        logger.warning(f"   Explanation: {event.explanation}")
        logger.warning(f"   Recommendation: {event.recommendation}")
    
    guardian.register_alert_callback(on_alert)
    
    # Start monitoring
    try:
        guardian.start_monitoring()
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        sys.exit(1)
    
    # Start web server in background
    server_config = config["server"]
    server_thread = threading.Thread(
        target=lambda: uvicorn.run(
            app,
            host=server_config["host"],
            port=server_config["port"],
            log_level=server_config["log_level"].lower()
        ),
        daemon=True
    )
    server_thread.start()
    
    logger.info(f"TinyGuardian started. Dashboard: http://{server_config['host']}:{server_config['port']}")
    
    # Handle shutdown
    def signal_handler(sig, frame):
        logger.info("Shutting down...")
        guardian.stop_monitoring()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Keep running
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()

