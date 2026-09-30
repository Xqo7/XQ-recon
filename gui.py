import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
from datetime import datetime, timezone
import os


# ============================================================
# Application Information
# ============================================================

APP_NAME = "XQ | Python Recon Tool"
APP_VERSION = "GUI 2.0"


# ============================================================
# Theme
# ============================================================

BG_COLOR = "#111827"
PANEL_COLOR = "#1F2937"
TEXT_COLOR = "#F9FAFB"
SECONDARY_COLOR = "#9CA3AF"
ENTRY_COLOR = "#374151"
ACCENT_COLOR = "#2563EB"


# ============================================================
# Global State
# ============================================================

last_results = None
scan_running = False


# ============================================================
# Helper Functions
# ============================================================

def get_target():
    target = target_entry.get().strip()

    if not target:
        messagebox.showwarning(
            "Missing Target",
            "Please enter a target."
        )
        return None

    return target


def clear_all():
    global last_results

    last_results = None

    for widget in result_widgets:
        widget.delete("1.0", tk.END)

    progress.stop()
    progress.configure(mode="determinate")
    progress["value"] = 0

    status_var.set("Ready")


def write(widget, text):
    widget.insert(tk.END, text)
    widget.see(tk.END)


def show_error(title, error):
    messagebox.showerror(
        title,
        str(error)
    )


def set_running(running):
    global scan_running

    scan_running = running

    state = "disabled" if running else "normal"

    for button in action_buttons:
        button.configure(state=state)

    if running:
        progress.configure(mode="indeterminate")
        progress.start(10)
        status_var.set("Scanning...")
    else:
        progress.stop()
        progress.configure(mode="determinate")
        progress["value"] = 100
        status_var.set("Ready")


def run_in_thread(function):
    thread = threading.Thread(
        target=function,
        daemon=True
    )

    thread.start()


# ============================================================
# Full Scan
# ============================================================

def start_scan():
    target = get_target()

    if not target or scan_running:
        return

    clear_all()
    set_running(True)

    run_in_thread(
        lambda: full_scan_worker(target)
    )


def full_scan_worker(target):
    global last_results

    try:
        from recon.scanner import scan

        results = scan(target)

        last_results = results

        root.after(
            0,
            lambda: display_full_scan(results)
        )

    except Exception as error:

        root.after(
            0,
            lambda: show_error(
                "Scan Error",
                error
            )
        )

    finally:

        root.after(
            0,
            lambda: set_running(False)
        )


def display_full_scan(results):

    overview_text.delete("1.0", tk.END)
    headers_text.delete("1.0", tk.END)
    tech_text.delete("1.0", tk.END)

    write(
        overview_text,
        f"{APP_NAME}\n"
    )

    write(
        overview_text,
        "=" * 60 + "\n\n"
    )

    fields = [
        ("Target", results.get("domain")),
        ("IP Address", results.get("ip")),
        ("Status Code", results.get("status_code")),
        ("Server", results.get("server")),
        ("Content-Type", results.get("content_type")),
        ("Final URL", results.get("final_url")),
        ("Redirects", results.get("redirects")),
        ("Response Time", f"{results.get('response_time')}s"),
    ]

    for name, value in fields:

        write(
            overview_text,
            f"{name:<18}: {value}\n"
        )

    write(
        headers_text,
        "SECURITY HEADERS\n"
    )

    write(
        headers_text,
        "=" * 60 + "\n\n"
    )

    for header, value in results.get(
        "security_headers",
        {}
    ).items():

        status = "FOUND" if value else "MISSING"

        write(
            headers_text,
            f"[{status}] {header}\n"
        )

    write(
        tech_text,
        "TECHNOLOGIES\n"
    )

    write(
        tech_text,
        "=" * 60 + "\n\n"
    )

    technologies = results.get(
        "technologies",
        []
    )

    if technologies:

        for technology in technologies:

            write(
                tech_text,
                f"• {technology}\n"
            )

    else:

        write(
            tech_text,
            "No technologies detected.\n"
        )


# ============================================================
# DNS
# ============================================================

def dns_scan():

    target = get_target()

    if not target or scan_running:
        return

    clear_all()
    set_running(True)

    run_in_thread(
        lambda: dns_worker(target)
    )


def dns_worker(target):

    try:

        from recon.dns import dns_lookup

        ip = dns_lookup(target)

        root.after(
            0,
            lambda: display_dns(
                target,
                ip
            )
        )

    except Exception as error:

        root.after(
            0,
            lambda: show_error(
                "DNS Error",
                error
            )
        )

    finally:

        root.after(
            0,
            lambda: set_running(False)
        )


def display_dns(target, ip):

    dns_text.delete(
        "1.0",
        tk.END
    )

    write(
        dns_text,
        "DNS LOOKUP\n"
    )

    write(
        dns_text,
        "=" * 60 + "\n\n"
    )

    write(
        dns_text,
        f"Domain      : {target}\n"
    )

    if ip:

        write(
            dns_text,
            f"IP Address  : {ip}\n\n"
        )

        write(
            dns_text,
            "Status      : SUCCESS\n"
        )

    else:

        write(
            dns_text,
            "IP Address  : Not Found\n\n"
        )

        write(
            dns_text,
            "Status      : FAILED\n"
        )


# ============================================================
# Headers
# ============================================================

def headers_scan():

    target = get_target()

    if not target or scan_running:
        return

    clear_all()
    set_running(True)

    run_in_thread(
        lambda: headers_worker(target)
    )


def headers_worker(target):

    try:

        from recon.http import http_check
        from recon.security import security_headers_check

        response = http_check(target)

        if response is None:

            raise RuntimeError(
                "HTTP request failed."
            )

        headers = security_headers_check(
            response
        )

        root.after(
            0,
            lambda: display_headers(
                response,
                headers
            )
        )

    except Exception as error:

        root.after(
            0,
            lambda: show_error(
                "Headers Error",
                error
            )
        )

    finally:

        root.after(
            0,
            lambda: set_running(False)
        )


def display_headers(response, headers):

    headers_text.delete(
        "1.0",
        tk.END
    )

    write(
        headers_text,
        "SECURITY HEADERS\n"
    )

    write(
        headers_text,
        "=" * 60 + "\n\n"
    )

    write(
        headers_text,
        f"URL         : {response.url}\n"
    )

    write(
        headers_text,
        f"Status Code : {response.status_code}\n\n"
    )

    for header, value in headers.items():

        if value:

            write(
                headers_text,
                f"[FOUND] {header}\n"
            )

            write(
                headers_text,
                f"        {value}\n\n"
            )

        else:

            write(
                headers_text,
                f"[MISSING] {header}\n\n"
            )


# ============================================================
# Subdomains
# ============================================================

def subdomains_scan():

    target = get_target()

    if not target or scan_running:
        return

    clear_all()
    set_running(True)

    workers = workers_var.get()

    run_in_thread(
        lambda: subdomains_worker(
            target,
            workers
        )
    )


def subdomains_worker(target, workers):

    try:

        from recon.subdomains import discover_subdomains

        wordlist_path = "wordlists/common.txt"

        with open(
            wordlist_path,
            "r",
            encoding="utf-8"
        ) as file:

            wordlist = file.readlines()

        results = discover_subdomains(
            target,
            wordlist,
            max_workers=workers
        )

        root.after(
            0,
            lambda: display_subdomains(
                target,
                results,
                wordlist_path,
                workers
            )
        )

    except Exception as error:

        root.after(
            0,
            lambda: show_error(
                "Subdomain Error",
                error
            )
        )

    finally:

        root.after(
            0,
            lambda: set_running(False)
        )


def display_subdomains(
    target,
    results,
    wordlist_path,
    workers
):

    subdomains_text.delete(
        "1.0",
        tk.END
    )

    write(
        subdomains_text,
        "SUBDOMAIN DISCOVERY\n"
    )

    write(
        subdomains_text,
        "=" * 60 + "\n\n"
    )

    write(
        subdomains_text,
        f"Target   : {target}\n"
    )

    write(
        subdomains_text,
        f"Wordlist : {wordlist_path}\n"
    )

    write(
        subdomains_text,
        f"Workers  : {workers}\n\n"
    )

    write(
        subdomains_text,
        f"Found: {len(results)}\n\n"
    )

    if results:

        for item in results:

            write(
                subdomains_text,
                f"• {item['subdomain']} -> {item['ip']}\n"
            )

    else:

        write(
            subdomains_text,
            "No subdomains found.\n"
        )


# ============================================================
# Ports
# ============================================================

def ports_scan():

    target = get_target()

    if not target or scan_running:
        return

    ports_input = ports_entry.get().strip()

    if not ports_input:

        messagebox.showwarning(
            "Missing Ports",
            "Please enter at least one port."
        )

        return

    try:

        ports = [
            int(port.strip())
            for port in ports_input.split(",")
        ]

    except ValueError:

        messagebox.showerror(
            "Invalid Ports",
            "Use numbers separated by commas.\n\n"
            "Example: 22,80,443"
        )

        return

    for port in ports:

        if not 1 <= port <= 65535:

            messagebox.showerror(
                "Invalid Port",
                f"Invalid port: {port}"
            )

            return

    clear_all()
    set_running(True)

    run_in_thread(
        lambda: ports_worker(
            target,
            ports
        )
    )


def ports_worker(target, ports):

    try:

        from recon.ports import scan_ports

        results = scan_ports(
            target,
            ports
        )

        root.after(
            0,
            lambda: display_ports(
                target,
                results
            )
        )

    except Exception as error:

        root.after(
            0,
            lambda: show_error(
                "Port Scan Error",
                error
            )
        )

    finally:

        root.after(
            0,
            lambda: set_running(False)
        )


def display_ports(target, results):

    ports_text.delete(
        "1.0",
        tk.END
    )

    write(
        ports_text,
        "PORT SCAN\n"
    )

    write(
        ports_text,
        "=" * 60 + "\n\n"
    )

    write(
        ports_text,
        f"Target: {target}\n\n"
    )

    for result in results:

        status = (
            "OPEN"
            if result["open"]
            else "CLOSED"
        )

        write(
            ports_text,
            f"{result['port']}/tcp"
            f"  {status}"
            f"  [{result['service']}]\n"
        )


# ============================================================
# Copy Results
# ============================================================

def copy_results():

    current_tab = notebook.index(
        notebook.select()
    )

    widget = result_widgets[current_tab]

    content = widget.get(
        "1.0",
        tk.END
    ).strip()

    if not content:

        messagebox.showinfo(
            "Copy Results",
            "There are no results to copy."
        )

        return

    root.clipboard_clear()
    root.clipboard_append(content)
    root.update()

    status_var.set(
        "Results copied to clipboard"
    )


# ============================================================
# Export JSON
# ============================================================

def export_json():

    if last_results is None:

        messagebox.showinfo(
            "Export JSON",
            "Run a Full Scan first."
        )

        return

    target = last_results.get(
        "domain",
        "scan"
    )

    filename = (
        f"reports/{target}-gui.json"
    )

    try:

        os.makedirs(
            "reports",
            exist_ok=True
        )

        report = {
            "tool": {
                "name": APP_NAME,
                "version": APP_VERSION
            },
            "scan": {
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "target": target
            },
            "data": last_results
        }

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4
            )

        messagebox.showinfo(
            "Export JSON",
            f"Report saved to:\n{filename}"
        )

    except Exception as error:

        show_error(
            "Export Error",
            error
        )


# ============================================================
# Main Window
# ============================================================

root = tk.Tk()

root.title(
    APP_NAME
)

root.geometry(
    "1100x750"
)

root.minsize(
    900,
    650
)

root.configure(
    bg=BG_COLOR
)


# ============================================================
# Styles
# ============================================================

style = ttk.Style()

style.theme_use(
    "clam"
)

style.configure(
    "TFrame",
    background=BG_COLOR
)

style.configure(
    "Panel.TFrame",
    background=PANEL_COLOR
)

style.configure(
    "TLabel",
    background=BG_COLOR,
    foreground=TEXT_COLOR
)

style.configure(
    "Title.TLabel",
    background=BG_COLOR,
    foreground=TEXT_COLOR,
    font=("Arial", 26, "bold")
)

style.configure(
    "Subtitle.TLabel",
    background=BG_COLOR,
    foreground=SECONDARY_COLOR,
    font=("Arial", 11)
)

style.configure(
    "TButton",
    padding=8,
    font=("Arial", 10)
)

style.configure(
    "TNotebook",
    background=BG_COLOR,
    borderwidth=0
)

style.configure(
    "TNotebook.Tab",
    padding=(15, 8),
    font=("Arial", 10)
)

style.configure(
    "Horizontal.TProgressbar",
    troughcolor=ENTRY_COLOR,
    background=ACCENT_COLOR
)


# ============================================================
# Header
# ============================================================

title = ttk.Label(
    root,
    text=APP_NAME,
    style="Title.TLabel"
)

title.pack(
    pady=(20, 3)
)


subtitle = ttk.Label(
    root,
    text="Authorized Reconnaissance & Security Analysis",
    style="Subtitle.TLabel"
)

subtitle.pack(
    pady=(0, 20)
)


# ============================================================
# Target
# ============================================================

target_frame = ttk.Frame(
    root,
    style="Panel.TFrame"
)

target_frame.pack(
    fill="x",
    padx=30
)


target_label = ttk.Label(
    target_frame,
    text="Target:"
)

target_label.pack(
    side="left",
    padx=10,
    pady=12
)


target_entry = ttk.Entry(
    target_frame,
    font=("Arial", 12)
)

target_entry.pack(
    side="left",
    fill="x",
    expand=True,
    padx=10,
    pady=10
)


# ============================================================
# Options
# ============================================================

options_frame = ttk.Frame(
    root
)

options_frame.pack(
    fill="x",
    padx=30,
    pady=12
)


workers_label = ttk.Label(
    options_frame,
    text="Subdomain Workers:"
)

workers_label.pack(
    side="left"
)


workers_var = tk.IntVar(
    value=4
)


workers_spinbox = ttk.Spinbox(
    options_frame,
    from_=1,
    to=8,
    textvariable=workers_var,
    width=5
)

workers_spinbox.pack(
    side="left",
    padx=(8, 25)
)


ports_label = ttk.Label(
    options_frame,
    text="Ports:"
)

ports_label.pack(
    side="left"
)


ports_entry = ttk.Entry(
    options_frame,
    width=35
)

ports_entry.insert(
    0,
    "21,22,25,53,80,443,8080"
)

ports_entry.pack(
    side="left",
    padx=8
)


# ============================================================
# Buttons
# ============================================================

button_frame = ttk.Frame(
    root
)

button_frame.pack(
    pady=8
)


scan_button = ttk.Button(
    button_frame,
    text="Full Scan",
    command=start_scan
)

scan_button.grid(
    row=0,
    column=0,
    padx=4
)


dns_button = ttk.Button(
    button_frame,
    text="DNS",
    command=dns_scan
)

dns_button.grid(
    row=0,
    column=1,
    padx=4
)


headers_button = ttk.Button(
    button_frame,
    text="Headers",
    command=headers_scan
)

headers_button.grid(
    row=0,
    column=2,
    padx=4
)


subdomains_button = ttk.Button(
    button_frame,
    text="Subdomains",
    command=subdomains_scan
)

subdomains_button.grid(
    row=0,
    column=3,
    padx=4
)


ports_button = ttk.Button(
    button_frame,
    text="Ports",
    command=ports_scan
)

ports_button.grid(
    row=0,
    column=4,
    padx=4
)


clear_button = ttk.Button(
    button_frame,
    text="Clear",
    command=clear_all
)

clear_button.grid(
    row=0,
    column=5,
    padx=4
)


copy_button = ttk.Button(
    button_frame,
    text="Copy Results",
    command=copy_results
)

copy_button.grid(
    row=0,
    column=6,
    padx=4
)


export_button = ttk.Button(
    button_frame,
    text="Export JSON",
    command=export_json
)

export_button.grid(
    row=0,
    column=7,
    padx=4
)


action_buttons = [
    scan_button,
    dns_button,
    headers_button,
    subdomains_button,
    ports_button
]


# ============================================================
# Progress Bar
# ============================================================

progress = ttk.Progressbar(
    root,
    mode="determinate",
    style="Horizontal.TProgressbar"
)

progress.pack(
    fill="x",
    padx=30,
    pady=(5, 8)
)


# ============================================================
# Results Notebook
# ============================================================

notebook = ttk.Notebook(
    root
)

notebook.pack(
    fill="both",
    expand=True,
    padx=30,
    pady=(0, 10)
)


overview_tab = ttk.Frame(notebook)
dns_tab = ttk.Frame(notebook)
headers_tab = ttk.Frame(notebook)
tech_tab = ttk.Frame(notebook)
subdomains_tab = ttk.Frame(notebook)
ports_tab = ttk.Frame(notebook)


notebook.add(
    overview_tab,
    text="Overview"
)

notebook.add(
    dns_tab,
    text="DNS"
)

notebook.add(
    headers_tab,
    text="Headers"
)

notebook.add(
    tech_tab,
    text="Technologies"
)

notebook.add(
    subdomains_tab,
    text="Subdomains"
)

notebook.add(
    ports_tab,
    text="Ports"
)


# ============================================================
# Result Text Areas
# ============================================================

def create_result_text(parent):
    widget = tk.Text(
        parent,
        bg=PANEL_COLOR,
        fg=TEXT_COLOR,
        insertbackground=TEXT_COLOR,
        font=("Menlo", 12),
        wrap="word",
        borderwidth=0
    )

    widget.pack(
        fill="both",
        expand=True,
        padx=10,
        pady=10
    )

    return widget


overview_text = create_result_text(
    overview_tab
)

dns_text = create_result_text(
    dns_tab
)

headers_text = create_result_text(
    headers_tab
)

tech_text = create_result_text(
    tech_tab
)

subdomains_text = create_result_text(
    subdomains_tab
)

ports_text = create_result_text(
    ports_tab
)


result_widgets = [
    overview_text,
    dns_text,
    headers_text,
    tech_text,
    subdomains_text,
    ports_text
]


# ============================================================
# Status Bar
# ============================================================

status_var = tk.StringVar(
    value=f"{APP_NAME} • Ready"
)


status_label = ttk.Label(
    root,
    textvariable=status_var,
    style="Subtitle.TLabel"
)

status_label.pack(
    pady=(0, 10)
)


# ============================================================
# Start Application
# ============================================================

root.mainloop()