"""
Automated screenshot capture for TinyGuardian documentation.
"""

from playwright.sync_api import sync_playwright
import time
import os

SCREENSHOTS_DIR = "docs/screenshots"


def capture_screenshots():
    """Capture all required screenshots."""
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        page.set_viewport_size({"width": 1920, "height": 1080})
        
        # Navigate to dashboard
        print("Navigating to dashboard...")
        page.goto("http://localhost:8080")
        time.sleep(3)  # Wait for page to load
        
        # Capture main dashboard
        print("Capturing main dashboard...")
        page.screenshot(path=f"{SCREENSHOTS_DIR}/dashboard.png", full_page=True)
        
        browser.close()
        print(f"Screenshots saved to {SCREENSHOTS_DIR}/")


if __name__ == "__main__":
    print("Make sure TinyGuardian is running on http://localhost:8080")
    input("Press Enter when ready...")
    capture_screenshots()




