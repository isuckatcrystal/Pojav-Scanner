import flet as ft
import subprocess
import sys
import os
import requests
import threading
import time

# CONFIGURATION
SCANNER_FILENAME = "scanner.py"
# Replace this with your actual raw URL (e.g., GitHub Raw or Discord attachment link)
UPDATE_URL = "https://example.com/path/to/new/scanner.py" 

def main(page: ft.Page):
    page.title = "Python Scanner"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 20
    page.scroll = ft.ScrollMode.AUTO

    # --- UI Elements ---
    
    # Console Output Area
    console_output = ft.Text(
        value="Initializing...\nChecking for bundled scanner...", 
        font_family="monospace", 
        size=12,
        selectable=True
    )
    
    console_container = ft.Container(
        content=ft.Column([console_output], scroll=ft.ScrollMode.ALWAYS),
        bgcolor=ft.colors.BLACK54,
        padding=10,
        border_radius=5,
        height=400, # Fixed height for scrollability
        expand=True,
    )

    status_text = ft.Text("Status: Checking...", color=ft.colors.GREY_400)

    # --- Logic Functions ---

    def check_scanner_presence():
        path = os.path.join(os.path.dirname(__file__), SCANNER_FILENAME)
        if os.path.exists(path):
            console_output.value = ">>> SYSTEM: Scanner.py found bundled in app.\n>>> Ready to scan."
            status_text.value = "Status: Ready (Bundled)"
            status_text.color = ft.colors.GREEN_400
        else:
            console_output.value = f">>> ERROR: {SCANNER_FILENAME} is MISSING from the bundle.\n>>> Try 'Update Scanner' to download it."
            status_text.value = "Status: Error - Missing File"
            status_text.color = ft.colors.RED_400
        page.update()

    def log(message):
        """Updates the console output in the UI safely."""
        console_output.value += f"\n{message}"
        page.update()

    def run_scanner(e):
        """Executes the scanner.py script in a separate thread."""
        scan_btn.disabled = True
        update_btn.disabled = True
        console_output.value = ">>> Starting Scanner..."
        status_text.value = "Status: Running..."
        page.update()

        def _target():
            scanner_path = os.path.join(os.path.dirname(__file__), SCANNER_FILENAME)
            
            if not os.path.exists(scanner_path):
                log(f"ERROR: {SCANNER_FILENAME} not found!")
                reset_ui()
                return

            try:
                # Execute scanner.py using the bundled Python interpreter
                process = subprocess.Popen(
                    [sys.executable, scanner_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )
                
                log(">>> Process started. If no output appears, check permissions.")

                # Read output line by line
                for line in process.stdout:
                    log(line.strip())
                
                # Read errors if any
                for line in process.stderr:
                    log(f"ERR: {line.strip()}")
                    if "Permission denied" in line:
                         log("\n>>> PERMISSION ERROR DETECTED!")
                         log(">>> Please go to Android Settings -> Apps -> Python Scanner -> Permissions")
                         log(">>> And enable 'All Files Access' or 'Storage'.")

                process.wait()
                log(f">>> Process finished with code {process.returncode}")

            except Exception as ex:
                log(f"CRITICAL ERROR: {str(ex)}")
            
            reset_ui()

        threading.Thread(target=_target, daemon=True).start()

    def update_scanner(e):
        """Downloads a new scanner.py from the remote URL."""
        update_btn.disabled = True
        status_text.value = "Status: Updating..."
        log(f"\n>>> Downloading update from {UPDATE_URL}...")
        page.update()

        def _target():
            try:
                response = requests.get(UPDATE_URL, timeout=10)
                response.raise_for_status()
                
                save_path = os.path.join(os.path.dirname(__file__), SCANNER_FILENAME)
                
                # Write the new content
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(response.text)
                
                log(">>> Update SUCCESS! New scanner.py saved.")
                status_text.value = "Status: Updated"
                
            except Exception as ex:
                log(f">>> Update FAILED: {str(ex)}")
            
            reset_ui()

        threading.Thread(target=_target, daemon=True).start()

    def reset_ui():
        scan_btn.disabled = False
        update_btn.disabled = False
        if "Error" not in status_text.value:
             status_text.value = "Status: Idle"
        page.update()

    # --- Layout ---
    
    scan_btn = ft.ElevatedButton(
        "START SCAN", 
        icon=ft.icons.PLAY_ARROW, 
        on_click=run_scanner,
        style=ft.ButtonStyle(
            color=ft.colors.WHITE,
            bgcolor=ft.colors.GREEN_600,
            shape=ft.RoundedRectangleBorder(radius=5),
        ),
        height=50
    )

    update_btn = ft.ElevatedButton(
        "UPDATE SCANNER", 
        icon=ft.icons.DOWNLOAD, 
        on_click=update_scanner,
        style=ft.ButtonStyle(
            color=ft.colors.WHITE,
            bgcolor=ft.colors.BLUE_600,
            shape=ft.RoundedRectangleBorder(radius=5),
        ),
        height=50
    )

    page.add(
        ft.Text("Python Scanner", size=24, weight=ft.FontWeight.BOLD),
        console_container,
        status_text,
        ft.Column([
            scan_btn,
            update_btn,
        ], spacing=10)
    )
    
    # Run startup check
    check_scanner_presence()

ft.app(target=main)
