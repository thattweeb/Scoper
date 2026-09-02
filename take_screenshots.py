"""
Automated screenshot capture for Scoper report.
Interacts with the running Scoper app to capture all report figures.
"""
import sys
import os
import time

screenshots_dir = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(screenshots_dir, exist_ok=True)

import pyautogui
import pygetwindow as gw

pyautogui.FAILSAFE = False

def find_scoper_window():
    """Find the Scoper application window (not the VS Code one)."""
    all_wins = gw.getAllWindows()
    for w in all_wins:
        if w.title == 'Scoper':
            return w
    return None

def focus_scoper():
    """Bring Scoper window to front and maximize."""
    win = find_scoper_window()
    if win:
        if win.isMinimized:
            win.restore()
        win.activate()
        time.sleep(0.3)
        win.maximize()
        time.sleep(0.5)
        return win
    else:
        print("ERROR: Scoper window not found!")
        return None

def take_screenshot(name, delay=0.5):
    """Take full-screen screenshot focused on Scoper."""
    win = focus_scoper()
    if not win:
        return None
    time.sleep(delay)
    # Capture just the Scoper window
    screenshot = pyautogui.screenshot(region=(
        max(0, win.left),
        max(0, win.top),
        win.width,
        win.height
    ))
    path = os.path.join(screenshots_dir, f"{name}.png")
    screenshot.save(path)
    print(f"[OK] Saved: {name}.png")
    return path

def click_button_by_text(text, win):
    """Try to locate and click a button. Returns True if clicked."""
    # Use pyautogui to locate text on screen
    try:
        loc = pyautogui.locateOnScreen(text)
        if loc:
            pyautogui.click(loc)
            return True
    except:
        pass
    return False

def main():
    step = sys.argv[1] if len(sys.argv) > 1 else "all"
    
    win = focus_scoper()
    if not win:
        print("Cannot find Scoper window. Make sure Scoper is running.")
        return
    
    print(f"Scoper window found: {win.left}, {win.top}, {win.width}, {win.height}")
    
    if step in ("start", "all"):
        # === Step 1: Click Start Capture button ===
        print("\n[Step 1] Clicking Start Capture...")
        # The Start Capture button is approximately at the left area of the toolbar
        # Based on the screenshot: Start Capture is around x=70, y=181 relative to window
        btn_x = win.left + 70
        btn_y = win.top + 181
        pyautogui.click(btn_x, btn_y)
        print(f"  Clicked at ({btn_x}, {btn_y})")
        
        # Wait for packets to accumulate
        print("  Waiting 8 seconds for packets to accumulate...")
        time.sleep(8)
        
        # Take main window screenshot with live data
        take_screenshot("fig1_main_window_overview", delay=1)
    
    if step in ("details", "all"):
        # === Step 2: Click a packet row to show details ===
        print("\n[Step 2] Clicking a packet row for details view...")
        # Click somewhere in the packet table (middle area)
        row_x = win.left + 400
        row_y = win.top + 280
        pyautogui.click(row_x, row_y)
        time.sleep(1)
        take_screenshot("fig2_protocol_details", delay=1)
    
    if step in ("hex", "all"):
        # === Step 3: Click Hex/ASCII tab ===
        print("\n[Step 3] Switching to Hex/ASCII view...")
        # Hex/ASCII tab is in the right panel tabs
        hex_x = win.left + 1050  # Approximate position of Hex/ASCII tab
        hex_y = win.top + 110
        pyautogui.click(hex_x, hex_y)
        time.sleep(1)
        take_screenshot("fig3_hex_ascii_view", delay=1)
    
    if step in ("filter", "all"):
        # === Step 4: Apply a display filter ===
        print("\n[Step 4] Applying display filter 'tcp'...")
        # Click the filter input field
        filter_x = win.left + 300
        filter_y = win.top + 147
        pyautogui.click(filter_x, filter_y)
        time.sleep(0.3)
        # Clear existing text and type filter
        pyautogui.hotkey('ctrl', 'a')
        time.sleep(0.1)
        pyautogui.typewrite('tcp', interval=0.05)
        time.sleep(0.3)
        # Click Apply Filter button
        apply_x = win.left + 597
        apply_y = win.top + 147
        pyautogui.click(apply_x, apply_y)
        time.sleep(1)
        
        # Switch back to Packet Details tab first
        pd_x = win.left + 940
        pd_y = win.top + 110
        pyautogui.click(pd_x, pd_y)
        time.sleep(0.5)
        
        take_screenshot("fig4_display_filter", delay=1)
    
    if step in ("dashboard", "all"):
        # === Step 5: Dashboard screenshot (bottom panel) ===
        print("\n[Step 5] Capturing monitoring dashboard...")
        take_screenshot("fig5_monitoring_dashboard", delay=1)
    
    if step in ("ai", "all"):
        # === Step 6: AI Copilot tab ===
        print("\n[Step 6] Switching to AI Assistant tab...")
        ai_x = win.left + 1250
        ai_y = win.top + 110
        pyautogui.click(ai_x, ai_y)
        time.sleep(1)
        take_screenshot("fig6_ai_copilot", delay=1)
    
    if step in ("stop", "all"):
        # === Step 7: Stop capture and take final screenshot ===
        print("\n[Step 7] Stopping capture for clean final screenshot...")
        stop_x = win.left + 195
        stop_y = win.top + 181
        pyautogui.click(stop_x, stop_y)
        time.sleep(1)
        
        # Switch back to Packet Details
        pd_x = win.left + 940
        pd_y = win.top + 110
        pyautogui.click(pd_x, pd_y)
        time.sleep(0.5)
        
        # Click a packet to show details
        row_x = win.left + 400
        row_y = win.top + 300
        pyautogui.click(row_x, row_y)
        time.sleep(0.5)
        
        take_screenshot("fig7_full_interface", delay=1)
    
    # Clear the filter for a clean state
    if step == "all":
        print("\n[Step 8] Clearing filter for clean capture overview...")
        filter_x = win.left + 300
        filter_y = win.top + 147
        pyautogui.click(filter_x, filter_y)
        time.sleep(0.2)
        pyautogui.hotkey('ctrl', 'a')
        pyautogui.press('delete')
        time.sleep(0.2)
        apply_x = win.left + 597
        apply_y = win.top + 147
        pyautogui.click(apply_x, apply_y)
        time.sleep(1)
        
        # Click a packet row
        row_x = win.left + 400
        row_y = win.top + 260
        pyautogui.click(row_x, row_y)
        time.sleep(0.5)
        
        take_screenshot("fig8_capture_overview", delay=1)
    
    print("\n=== All screenshots saved to ./screenshots/ ===")

if __name__ == "__main__":
    main()
