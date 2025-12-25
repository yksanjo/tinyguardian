"""
Simulate IoT device logs for testing.
"""

import paho.mqtt.client as mqtt
import time
import random
from datetime import datetime


def simulate_logs(broker="localhost", port=1883, interval=2):
    """Simulate IoT device logs via MQTT."""
    client = mqtt.Client(client_id="iot_simulator")
    
    devices = ["smart_camera_01", "door_lock_02", "sensor_03", "thermostat_04"]
    
    normal_logs = [
        "Device started successfully",
        "Temperature reading: 72.5°F",
        "Motion detected in zone 1",
        "Door locked",
        "Scheduled check-in completed",
    ]
    
    suspicious_logs = [
        "Failed login attempt from 192.168.1.100",
        "Unauthorized access attempt detected",
        "Multiple failed authentication attempts",
        "Configuration changed without authorization",
        "Unusual network activity detected",
        "Connection from unknown IP: 10.0.0.50",
    ]
    
    try:
        client.connect(broker, port, 60)
        print(f"Connected to MQTT broker {broker}:{port}")
        
        while True:
            device = random.choice(devices)
            
            # 20% chance of suspicious log
            if random.random() < 0.2:
                log = random.choice(suspicious_logs)
            else:
                log = random.choice(normal_logs)
            
            topic = f"iot/devices/{device}/logs"
            message = f"[{datetime.now().isoformat()}] {log}"
            
            client.publish(topic, message)
            print(f"Published to {topic}: {message}")
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped simulation")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Simulate IoT device logs")
    parser.add_argument("--broker", default="localhost", help="MQTT broker")
    parser.add_argument("--port", type=int, default=1883, help="MQTT port")
    parser.add_argument("--interval", type=int, default=2, help="Log interval (seconds)")
    
    args = parser.parse_args()
    simulate_logs(args.broker, args.port, args.interval)




