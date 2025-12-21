# Screenshots Directory

This directory contains screenshots of the TinyGuardian user interface.

## How to Generate Screenshots

1. Start TinyGuardian:
   ```bash
   python main.py
   ```

2. In another terminal, simulate IoT logs:
   ```bash
   python scripts/simulate_iot_logs.py
   ```

3. Open the dashboard:
   ```
   http://localhost:8080
   ```

4. Wait for alerts to appear, then capture screenshots.

## Required Screenshots

- `dashboard.png` - Main dashboard
- `dashboard-overview.png` - Full dashboard view
- `alerts-list.png` - Alert cards with explanations
- `device-status.png` - Device status panel
- `event-timeline.png` - Event timeline visualization
- `alert-details.png` - Alert detail modal
- `settings.png` - Settings/configuration page

