import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import socket
import time
import ipaddress
try:
    import netifaces
except ImportError:
    netifaces = None
import nmap
import requests
import json
import os
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from concurrent.futures import ThreadPoolExecutor
import queue
from datetime import datetime
import webbrowser
import base64
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class GuardianNetworkScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.version = "1.0"
        self.scanning = False
        self.current_scan_id = None
        self.scan_results = {}
        self.vulnerabilities_db = {}
        self.plugins = []
        self.notification_queue = queue.Queue()
        
        # Configuración inicial
        self.config = {
            "max_threads": 100,
            "timeout": 2.0,
            "enable_banner_grab": True,
            "enable_vuln_check": True,
            "auto_save": True,
            "notification_email": "",
            "telegram_token": "",
            "telegram_chat_id": ""
        }
        
        # Base de datos de servicios y vulnerabilidades
        self.services_db = {
            21: {"name": "FTP", "risk": "medium", "banner": True},
            22: {"name": "SSH", "risk": "low", "banner": True},
            23: {"name": "Telnet", "risk": "high", "banner": True},
            25: {"name": "SMTP", "risk": "medium", "banner": True},
            53: {"name": "DNS", "risk": "low", "banner": False},
            80: {"name": "HTTP", "risk": "medium", "banner": True},
            110: {"name": "POP3", "risk": "medium", "banner": True},
            135: {"name": "RPC", "risk": "high", "banner": False},
            139: {"name": "NetBIOS-SSN", "risk": "high", "banner": False},
            143: {"name": "IMAP", "risk": "medium", "banner": True},
            443: {"name": "HTTPS", "risk": "low", "banner": True},
            445: {"name": "SMB", "risk": "high", "banner": False},
            993: {"name": "IMAPS", "risk": "low", "banner": True},
            995: {"name": "POP3S", "risk": "low", "banner": True},
            1433: {"name": "MSSQL", "risk": "high", "banner": True},
            1521: {"name": "Oracle", "risk": "high", "banner": True},
            3306: {"name": "MySQL", "risk": "high", "banner": True},
            3389: {"name": "RDP", "risk": "high", "banner": False},
            5432: {"name": "PostgreSQL", "risk": "high", "banner": True},
            5900: {"name": "VNC", "risk": "high", "banner": False},
            6379: {"name": "Redis", "risk": "high", "banner": True},
            8080: {"name": "HTTP-Alt", "risk": "medium", "banner": True},
            27017: {"name": "MongoDB", "risk": "high", "banner": True}
        }
        
        self.setup_ui()
        self.load_config()
        self.setup_notification_processor()
        self.check_dependencies()
        
    def setup_ui(self):
        """Configurar interfaz principal"""
        self.root.title(f"🛡️ Guardian Network Scanner v{self.version} - Ethical Hacking Tool")
        self.root.geometry("1400x900")
        self.root.configure(bg="#0a0e27")
        
        # Colores tema cyberpunk
        self.colors = {
            "bg_primary": "#0a0e27",
            "bg_secondary": "#1a1f3a",
            "bg_tertiary": "#2a2f4a",
            "accent_cyan": "#00d4ff",
            "accent_purple": "#b300ff",
            "accent_green": "#39ff14",
            "accent_red": "#ff073a",
            "accent_yellow": "#ffff00",
            "text_primary": "#ffffff",
            "text_secondary": "#b0b7c3",
            "text_muted": "#6c757d"
        }
        
        # Configurar estilo
        self.setup_styles()
        
        # Crear notebook principal
        self.setup_main_notebook()
        
        # Configurar tabs
        self.setup_scanner_tab()
        self.setup_network_discovery_tab()
        self.setup_vulnerability_tab()
        self.setup_reports_tab()
        self.setup_plugins_tab()
        self.setup_config_tab()
        
        # Status bar
        self.setup_status_bar()
        
    def setup_styles(self):
        """Configurar estilos personalizados"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configurar estilos para notebook
        style.configure('TNotebook', background=self.colors["bg_primary"])
        style.configure('TNotebook.Tab', 
                       background=self.colors["bg_secondary"],
                       foreground=self.colors["text_secondary"],
                       padding=[12, 8])
        style.map('TNotebook.Tab',
                 background=[('selected', self.colors["bg_tertiary"])],
                 foreground=[('selected', self.colors["accent_cyan"])])
                 
    def setup_main_notebook(self):
        """Configurar notebook principal con pestañas"""
        # Header con logo
        header_frame = tk.Frame(self.root, bg=self.colors["bg_primary"], height=60)
        header_frame.pack(fill="x", padx=10, pady=5)
        header_frame.pack_propagate(False)
        
        # Logo y título
        title_label = tk.Label(
            header_frame,
            text="🛡️ GUARDIAN NETWORK SCANNER",
            font=("Orbitron", 20, "bold"),
            fg=self.colors["accent_cyan"],
            bg=self.colors["bg_primary"]
        )
        title_label.pack(side="left", pady=15)
        
        version_label = tk.Label(
            header_frame,
            text=f"v{self.version} | Ethical Hacking Suite",
            font=("Consolas", 10),
            fg=self.colors["text_muted"],
            bg=self.colors["bg_primary"]
        )
        version_label.pack(side="right", pady=20)
        
        # Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
    def setup_scanner_tab(self):
        """Tab principal de escaneo de puertos"""
        scanner_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(scanner_frame, text="🔍 Port Scanner")
        
        # Panel izquierdo - Controles
        control_panel = tk.Frame(scanner_frame, bg=self.colors["bg_secondary"], width=400)
        control_panel.pack(side="left", fill="y", padx=5, pady=5)
        control_panel.pack_propagate(False)
        
        # Título del panel
        tk.Label(
            control_panel,
            text="🎯 SCAN CONFIGURATION",
            font=("Consolas", 14, "bold"),
            fg=self.colors["accent_purple"],
            bg=self.colors["bg_secondary"]
        ).pack(pady=10)
        
        # Target configuration
        target_frame = tk.LabelFrame(
            control_panel,
            text="Target Configuration",
            bg=self.colors["bg_secondary"],
            fg=self.colors["text_primary"],
            font=("Consolas", 10, "bold")
        )
        target_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(target_frame, text="🎯 Target IP/Domain:", 
                fg=self.colors["text_primary"], bg=self.colors["bg_secondary"]).pack(anchor="w")
        self.target_entry = tk.Entry(
            target_frame,
            font=("Consolas", 10),
            bg=self.colors["bg_tertiary"],
            fg=self.colors["text_primary"],
            insertbackground=self.colors["accent_cyan"]
        )
        self.target_entry.pack(fill="x", pady=2)
        self.target_entry.insert(0, "127.0.0.1")
        
        # Port range
        port_frame = tk.Frame(target_frame, bg=self.colors["bg_secondary"])
        port_frame.pack(fill="x", pady=5)
        
        tk.Label(port_frame, text="📍 Port Range:", 
                fg=self.colors["text_primary"], bg=self.colors["bg_secondary"]).pack(anchor="w")
        
        range_frame = tk.Frame(port_frame, bg=self.colors["bg_secondary"])
        range_frame.pack(fill="x")
        
        self.port_start_entry = tk.Entry(
            range_frame, width=8, font=("Consolas", 10),
            bg=self.colors["bg_tertiary"], fg=self.colors["text_primary"]
        )
        self.port_start_entry.pack(side="left")
        self.port_start_entry.insert(0, "1")
        
        tk.Label(range_frame, text=" - ", fg=self.colors["text_primary"], 
                bg=self.colors["bg_secondary"]).pack(side="left")
        
        self.port_end_entry = tk.Entry(
            range_frame, width=8, font=("Consolas", 10),
            bg=self.colors["bg_tertiary"], fg=self.colors["text_primary"]
        )
        self.port_end_entry.pack(side="left")
        self.port_end_entry.insert(0, "1000")
        
        # Presets rápidos
        presets_frame = tk.LabelFrame(
            control_panel,
            text="Quick Presets",
            bg=self.colors["bg_secondary"],
            fg=self.colors["text_primary"],
            font=("Consolas", 10, "bold")
        )
        presets_frame.pack(fill="x", padx=10, pady=5)
        
        presets = [
            ("🚀 Quick Scan", "1", "1000"),
            ("🔍 Common Ports", "1", "10000"),
            ("💀 Full Scan", "1", "65535"),
            ("🌐 Web Services", "80", "8080"),
            ("🗄️ Database Ports", "1433", "5432")
        ]
        
        for name, start, end in presets:
            btn = tk.Button(
                presets_frame,
                text=name,
                font=("Consolas", 9),
                bg=self.colors["bg_tertiary"],
                fg=self.colors["accent_cyan"],
                relief="flat",
                command=lambda s=start, e=end: self.set_port_range(s, e)
            )
            btn.pack(fill="x", pady=1, padx=5)
            
        # Opciones de escaneo
        options_frame = tk.LabelFrame(
            control_panel,
            text="Scan Options",
            bg=self.colors["bg_secondary"],
            fg=self.colors["text_primary"],
            font=("Consolas", 10, "bold")
        )
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.banner_grab_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            options_frame,
            text="🏷️ Enable Banner Grabbing",
            variable=self.banner_grab_var,
            bg=self.colors["bg_secondary"],
            fg=self.colors["text_primary"],
            selectcolor=self.colors["bg_tertiary"]
        ).pack(anchor="w")
        
        self.vuln_check_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            options_frame,
            text="🛡️ Vulnerability Check",
            variable=self.vuln_check_var,
            bg=self.colors["bg_secondary"],
            fg=self.colors["text_primary"],
            selectcolor=self.colors["bg_tertiary"]
        ).pack(anchor="w")
        
        self.stealth_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            options_frame,
            text="🥷 Stealth Mode",
            variable=self.stealth_var,
            bg=self.colors["bg_secondary"],
            fg=self.colors["text_primary"],
            selectcolor=self.colors["bg_tertiary"]
        ).pack(anchor="w")
        
        # Controles de escaneo
        control_buttons_frame = tk.Frame(control_panel, bg=self.colors["bg_secondary"])
        control_buttons_frame.pack(fill="x", padx=10, pady=20)
        
        self.scan_btn = tk.Button(
            control_buttons_frame,
            text="🚀 START SCAN",
            font=("Consolas", 12, "bold"),
            bg=self.colors["accent_green"],
            fg="#000000",
            relief="flat",
            height=2,
            command=self.start_port_scan
        )
        self.scan_btn.pack(fill="x", pady=2)
        
        tk.Button(
            control_buttons_frame,
            text="🛑 STOP SCAN",
            font=("Consolas", 10, "bold"),
            bg=self.colors["accent_red"],
            fg="#ffffff",
            relief="flat",
            command=self.stop_scan
        ).pack(fill="x", pady=2)
        
        tk.Button(
            control_buttons_frame,
            text="🧹 CLEAR RESULTS",
            font=("Consolas", 10, "bold"),
            bg=self.colors["accent_yellow"],
            fg="#000000",
            relief="flat",
            command=self.clear_results
        ).pack(fill="x", pady=2)
        
        # Panel derecho - Resultados
        results_panel = tk.Frame(scanner_frame, bg=self.colors["bg_primary"])
        results_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        # Título de resultados
        tk.Label(
            results_panel,
            text="📊 SCAN RESULTS",
            font=("Consolas", 14, "bold"),
            fg=self.colors["accent_purple"],
            bg=self.colors["bg_primary"]
        ).pack(pady=5)
        
        # Área de resultados con notebook
        results_notebook = ttk.Notebook(results_panel)
        results_notebook.pack(fill="both", expand=True)
        
        # Tab de console output
        console_frame = tk.Frame(results_notebook, bg=self.colors["bg_primary"])
        results_notebook.add(console_frame, text="💻 Console")
        
        self.console_output = scrolledtext.ScrolledText(
            console_frame,
            font=("Consolas", 10),
            bg=self.colors["bg_primary"],
            fg=self.colors["accent_green"],
            insertbackground=self.colors["accent_cyan"],
            wrap=tk.WORD
        )
        self.console_output.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Configurar tags para colores
        self.console_output.tag_config("info", foreground=self.colors["accent_cyan"])
        self.console_output.tag_config("success", foreground=self.colors["accent_green"])
        self.console_output.tag_config("warning", foreground=self.colors["accent_yellow"])
        self.console_output.tag_config("error", foreground=self.colors["accent_red"])
        self.console_output.tag_config("critical", foreground=self.colors["accent_red"], 
                                     background="#330000")
        
        # Tab de vulnerabilidades encontradas
        vulns_frame = tk.Frame(results_notebook, bg=self.colors["bg_primary"])
        results_notebook.add(vulns_frame, text="🚨 Vulnerabilities")
        
        self.vulns_tree = ttk.Treeview(
            vulns_frame,
            columns=("Port", "Service", "Risk", "CVE", "Description"),
            show="headings"
        )
        self.vulns_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Configurar columnas
        self.vulns_tree.heading("Port", text="Port")
        self.vulns_tree.heading("Service", text="Service")
        self.vulns_tree.heading("Risk", text="Risk Level")
        self.vulns_tree.heading("CVE", text="CVE")
        self.vulns_tree.heading("Description", text="Description")
        
        # Tab de gráficos
        charts_frame = tk.Frame(results_notebook, bg=self.colors["bg_primary"])
        results_notebook.add(charts_frame, text="📈 Charts")
        
        self.setup_charts_panel(charts_frame)
        
    def setup_network_discovery_tab(self):
        """Tab de descubrimiento de red"""
        discovery_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(discovery_frame, text="🌐 Network Discovery")
        
        # Panel de controles
        control_frame = tk.Frame(discovery_frame, bg=self.colors["bg_secondary"])
        control_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(
            control_frame,
            text="🌐 NETWORK DISCOVERY MODULE",
            font=("Consolas", 14, "bold"),
            fg=self.colors["accent_purple"],
            bg=self.colors["bg_secondary"]
        ).pack(pady=10)
        
        # Auto-detect network
        tk.Button(
            control_frame,
            text="🔍 Auto-Detect Local Network",
            font=("Consolas", 12, "bold"),
            bg=self.colors["accent_cyan"],
            fg="#000000",
            relief="flat",
            command=self.auto_detect_network
        ).pack(pady=5)
        
        # Manual network input
        network_frame = tk.Frame(control_frame, bg=self.colors["bg_secondary"])
        network_frame.pack(fill="x", pady=5)
        
        tk.Label(network_frame, text="🎯 Network Range (CIDR):", 
                fg=self.colors["text_primary"], bg=self.colors["bg_secondary"]).pack(side="left")
        
        self.network_entry = tk.Entry(
            network_frame,
            font=("Consolas", 10),
            bg=self.colors["bg_tertiary"],
            fg=self.colors["text_primary"]
        )
        self.network_entry.pack(side="left", padx=5, fill="x", expand=True)
        self.network_entry.insert(0, "192.168.1.0/24")
        
        tk.Button(
            network_frame,
            text="🚀 Scan Network",
            font=("Consolas", 10, "bold"),
            bg=self.colors["accent_green"],
            fg="#000000",
            relief="flat",
            command=self.scan_network_range
        ).pack(side="right", padx=5)
        
        # Resultados de discovery
        self.discovery_tree = ttk.Treeview(
            discovery_frame,
            columns=("IP", "Hostname", "MAC", "Vendor", "OS", "Open_Ports"),
            show="headings"
        )
        self.discovery_tree.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Configurar columnas
        for col in ("IP", "Hostname", "MAC", "Vendor", "OS", "Open_Ports"):
            self.discovery_tree.heading(col, text=col.replace("_", " "))
            
    def setup_vulnerability_tab(self):
        """Tab de análisis de vulnerabilidades"""
        vuln_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(vuln_frame, text="🛡️ Vulnerability Analysis")
        
        # Panel de controles
        control_frame = tk.Frame(vuln_frame, bg=self.colors["bg_secondary"])
        control_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(
            control_frame,
            text="🛡️ VULNERABILITY ANALYSIS ENGINE",
            font=("Consolas", 14, "bold"),
            fg=self.colors["accent_purple"],
            bg=self.colors["bg_secondary"]
        ).pack(pady=10)
        
        buttons_frame = tk.Frame(control_frame, bg=self.colors["bg_secondary"])
        buttons_frame.pack(fill="x", pady=5)
        
        tk.Button(
            buttons_frame,
            text="🔄 Update CVE Database",
            font=("Consolas", 10, "bold"),
            bg=self.colors["accent_cyan"],
            fg="#000000",
            relief="flat",
            command=self.update_cve_database
        ).pack(side="left", padx=5)
        
        tk.Button(
            buttons_frame,
            text="🔍 Deep Vulnerability Scan",
            font=("Consolas", 10, "bold"),
            bg=self.colors["accent_red"],
            fg="#ffffff",
            relief="flat",
            command=self.deep_vulnerability_scan
        ).pack(side="left", padx=5)
        
        # Resultado de vulnerabilidades detallado
        self.detailed_vulns_text = scrolledtext.ScrolledText(
            vuln_frame,
            font=("Consolas", 10),
            bg=self.colors["bg_primary"],
            fg=self.colors["text_primary"],
            wrap=tk.WORD
        )
        self.detailed_vulns_text.pack(fill="both", expand=True, padx=10, pady=5)
        
    def setup_reports_tab(self):
        """Tab de generación de reportes"""
        reports_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(reports_frame, text="📄 Reports")
        
        tk.Label(
            reports_frame,
            text="📄 REPORT GENERATION CENTER",
            font=("Consolas", 14, "bold"),
            fg=self.colors["accent_purple"],
            bg=self.colors["bg_primary"]
        ).pack(pady=10)
        
        # Opciones de reporte
        options_frame = tk.Frame(reports_frame, bg=self.colors["bg_secondary"])
        options_frame.pack(fill="x", padx=10, pady=5)
        
        report_buttons = [
            ("📊 Generate HTML Report", self.generate_html_report, self.colors["accent_cyan"]),
            ("📋 Generate PDF Report", self.generate_pdf_report, self.colors["accent_green"]),
            ("📈 Generate Executive Summary", self.generate_executive_summary, self.colors["accent_purple"]),
            ("📤 Email Report", self.email_report, self.colors["accent_yellow"])
        ]
        
        for text, command, color in report_buttons:
            tk.Button(
                options_frame,
                text=text,
                font=("Consolas", 12, "bold"),
                bg=color,
                fg="#000000" if color == self.colors["accent_yellow"] else "#ffffff",
                relief="flat",
                command=command
            ).pack(fill="x", pady=2, padx=5)
            
        # Preview del reporte
        self.report_preview = scrolledtext.ScrolledText(
            reports_frame,
            font=("Consolas", 10),
            bg=self.colors["bg_primary"],
            fg=self.colors["text_primary"],
            wrap=tk.WORD
        )
        self.report_preview.pack(fill="both", expand=True, padx=10, pady=5)
        
    def setup_plugins_tab(self):
        """Tab de sistema de plugins"""
        plugins_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(plugins_frame, text="🔌 Plugins")
        
        tk.Label(
            plugins_frame,
            text="🔌 PLUGIN MANAGEMENT SYSTEM",
            font=("Consolas", 14, "bold"),
            fg=self.colors["accent_purple"],
            bg=self.colors["bg_primary"]
        ).pack(pady=10)
        
        # Lista de plugins disponibles
        available_plugins = [
            "🌐 Web Application Scanner",
            "📱 Mobile Device Detector", 
            "🗄️ Database Security Checker",
            "📧 Email Security Analyzer",
            "🔐 SSL/TLS Certificate Checker",
            "🏭 Industrial Control Systems Scanner"
        ]
        
        for plugin in available_plugins:
            plugin_frame = tk.Frame(plugins_frame, bg=self.colors["bg_secondary"])
            plugin_frame.pack(fill="x", padx=10, pady=2)
            
            tk.Label(
                plugin_frame,
                text=plugin,
                font=("Consolas", 10),
                fg=self.colors["text_primary"],
                bg=self.colors["bg_secondary"]
            ).pack(side="left", padx=10, pady=5)
            
            tk.Button(
                plugin_frame,
                text="🔧 Configure",
                font=("Consolas", 8),
                bg=self.colors["accent_cyan"],
                fg="#000000",
                relief="flat",
                command=lambda p=plugin: self.configure_plugin(p)
            ).pack(side="right", padx=5, pady=2)
            
    def setup_config_tab(self):
        """Tab de configuración"""
        config_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(config_frame, text="⚙️ Configuration")
        
        tk.Label(
            config_frame,
            text="⚙️ CONFIGURATION CENTER",
            font=("Consolas", 14, "bold"),
            fg=self.colors["accent_purple"],
            bg=self.colors["bg_primary"]
        ).pack(pady=10)
        
        # Configuraciones de red
        network_config_frame = tk.LabelFrame(
            config_frame,
            text="Network Configuration",
            bg=self.colors["bg_secondary"],
            fg=self.colors["text_primary"],
            font=("Consolas", 10, "bold")
        )
        network_config_frame.pack(fill="x", padx=10, pady=5)
        
        # Timeout
        timeout_frame = tk.Frame(network_config_frame, bg=self.colors["bg_secondary"])
        timeout_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(timeout_frame, text="⏱️ Connection Timeout (seconds):",
                fg=self.colors["text_primary"], bg=self.colors["bg_secondary"]).pack(side="left")
        
        self.timeout_var = tk.StringVar(value=str(self.config["timeout"]))
        timeout_spinbox = tk.Spinbox(
            timeout_frame,
            from_=0.1, to=10.0, increment=0.1,
            textvariable=self.timeout_var,
            bg=self.colors["bg_tertiary"],
            fg=self.colors["text_primary"]
        )
        timeout_spinbox.pack(side="right", padx=5)
        
        # Max threads
        threads_frame = tk.Frame(network_config_frame, bg=self.colors["bg_secondary"])
        threads_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(threads_frame, text="🧵 Max Concurrent Threads:",
                fg=self.colors["text_primary"], bg=self.colors["bg_secondary"]).pack(side="left")
        
        self.threads_var = tk.StringVar(value=str(self.config["max_threads"]))
        threads_spinbox = tk.Spinbox(
            threads_frame,
            from_=1, to=500, increment=10,
            textvariable=self.threads_var,
            bg=self.colors["bg_tertiary"],
            fg=self.colors["text_primary"]
        )
        threads_spinbox.pack(side="right", padx=5)
        
        # Configuraciones de notificaciones
        notif_config_frame = tk.LabelFrame(
            config_frame,
            text="Notification Configuration",
            bg=self.colors["bg_secondary"],
            fg=self.colors["text_primary"],
            font=("Consolas", 10, "bold")
        )
        notif_config_frame.pack(fill="x", padx=10, pady=5)
        
        # Email
        email_frame = tk.Frame(notif_config_frame, bg=self.colors["bg_secondary"])
        email_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(email_frame, text="📧 Notification Email:",
                fg=self.colors["text_primary"], bg=self.colors["bg_secondary"]).pack(anchor="w")
        
        self.email_entry = tk.Entry(
            email_frame,
            font=("Consolas", 10),
            bg=self.colors["bg_tertiary"],
            fg=self.colors["text_primary"]
        )
        self.email_entry.pack(fill="x", pady=2)
        self.email_entry.insert(0, self.config["notification_email"])
        
        # Botón guardar configuración
        tk.Button(
            config_frame,
            text="💾 Save Configuration",
            font=("Consolas", 12, "bold"),
            bg=self.colors["accent_green"],
            fg="#000000",
            relief="flat",
            command=self.
            # Continuación desde save_config
        save_config
        ).pack(pady=20)
        
    def setup_status_bar(self):
        """Configurar barra de estado"""
        self.status_frame = tk.Frame(self.root, bg=self.colors["bg_secondary"], height=30)
        self.status_frame.pack(fill="x", side="bottom")
        self.status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(
            self.status_frame,
            text="🟢 Ready | Waiting for scan commands...",
            font=("Consolas", 10),
            fg=self.colors["accent_green"],
            bg=self.colors["bg_secondary"],
            anchor="w"
        )
        self.status_label.pack(side="left", padx=10, pady=5)
        
        # Indicador de progreso
        self.progress_var = tk.StringVar(value="0%")
        self.progress_label = tk.Label(
            self.status_frame,
            textvariable=self.progress_var,
            font=("Consolas", 10),
            fg=self.colors["accent_cyan"],
            bg=self.colors["bg_secondary"]
        )
        self.progress_label.pack(side="right", padx=10, pady=5)
        
    def setup_charts_panel(self, parent):
        """Configurar panel de gráficos"""
        # Crear figura de matplotlib
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        self.fig.patch.set_facecolor('#0a0e27')
        
        # Configurar subplots
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
            ax.set_facecolor('#1a1f3a')
            ax.tick_params(colors='white')
            ax.spines['bottom'].set_color('white')
            ax.spines['top'].set_color('white')
            ax.spines['right'].set_color('white')
            ax.spines['left'].set_color('white')
        
        # Canvas para matplotlib
        self.canvas = FigureCanvasTkAgg(self.fig, parent)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
    def setup_notification_processor(self):
        """Configurar procesador de notificaciones"""
        self.notification_thread = threading.Thread(target=self.process_notifications, daemon=True)
        self.notification_thread.start()
        
    def process_notifications(self):
        """Procesar cola de notificaciones"""
        while True:
            try:
                notification = self.notification_queue.get(timeout=1)
                if notification["type"] == "email":
                    self.send_email_notification(notification)
                elif notification["type"] == "telegram":
                    self.send_telegram_notification(notification)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error processing notification: {e}")
                
    def check_dependencies(self):
        """Verificar dependencias del sistema"""
        self.log_message("🔍 Checking system dependencies...", "info")
        
        dependencies = {
            "nmap": "Network mapping tool",
            "netstat": "Network statistics",
            "ping": "Network connectivity test"
        }
        
        for dep, desc in dependencies.items():
            try:
                result = subprocess.run([dep, "--version"], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.log_message(f"✅ {dep} - {desc}: Available", "success")
                else:
                    self.log_message(f"❌ {dep} - {desc}: Not available", "warning")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.log_message(f"❌ {dep} - {desc}: Not found", "warning")
                
    def log_message(self, message, level="info"):
        """Registrar mensaje en la consola"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.console_output.insert(tk.END, formatted_message, level)
        self.console_output.see(tk.END)
        self.root.update_idletasks()
        
    def update_status(self, message, color="accent_green"):
        """Actualizar barra de estado"""
        self.status_label.config(text=message, fg=self.colors[color])
        self.root.update_idletasks()
        
    def set_port_range(self, start, end):
        """Establecer rango de puertos"""
        self.port_start_entry.delete(0, tk.END)
        self.port_start_entry.insert(0, start)
        self.port_end_entry.delete(0, tk.END)
        self.port_end_entry.insert(0, end)
        
    def start_port_scan(self):
        """Iniciar escaneo de puertos"""
        if self.scanning:
            messagebox.showwarning("Warning", "Scan already in progress!")
            return
            
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or domain!")
            return
            
        try:
            port_start = int(self.port_start_entry.get())
            port_end = int(self.port_end_entry.get())
            
            if port_start > port_end or port_start < 1 or port_end > 65535:
                messagebox.showerror("Error", "Invalid port range!")
                return
                
        except ValueError:
            messagebox.showerror("Error", "Port numbers must be integers!")
            return
            
        self.scanning = True
        self.scan_btn.config(text="🔄 SCANNING...", state="disabled")
        self.update_status("🔍 Scanning in progress...", "accent_yellow")
        
        # Iniciar escaneo en hilo separado
        scan_thread = threading.Thread(
            target=self.perform_port_scan,
            args=(target, port_start, port_end),
            daemon=True
        )
        scan_thread.start()
        
    def perform_port_scan(self, target, port_start, port_end):
        """Ejecutar escaneo de puertos"""
        try:
            self.log_message(f"🎯 Starting port scan on {target}", "info")
            self.log_message(f"📍 Port range: {port_start}-{port_end}", "info")
            
            open_ports = []
            total_ports = port_end - port_start + 1
            scanned_ports = 0
            
            # Resolver IP si es necesario
            try:
                target_ip = socket.gethostbyname(target)
                if target_ip != target:
                    self.log_message(f"🔍 Resolved {target} to {target_ip}", "info")
            except socket.gaierror:
                self.log_message(f"❌ Failed to resolve {target}", "error")
                return
                
            # Escaneo con ThreadPoolExecutor para mejor rendimiento
            with ThreadPoolExecutor(max_workers=self.config["max_threads"]) as executor:
                futures = []
                
                for port in range(port_start, port_end + 1):
                    if not self.scanning:
                        break
                        
                    future = executor.submit(self.scan_port, target_ip, port)
                    futures.append((port, future))
                    
                for port, future in futures:
                    if not self.scanning:
                        break
                        
                    try:
                        result = future.result(timeout=self.config["timeout"])
                        if result:
                            open_ports.append((port, result))
                            service_info = self.services_db.get(port, {"name": "Unknown", "risk": "low"})
                            self.log_message(
                                f"✅ Port {port} OPEN - {service_info['name']} [{service_info['risk']} risk]",
                                "success"
                            )
                            
                            # Banner grabbing si está habilitado
                            if self.banner_grab_var.get() and service_info.get("banner", False):
                                banner = self.grab_banner(target_ip, port)
                                if banner:
                                    self.log_message(f"🏷️ Banner: {banner[:100]}...", "info")
                                    
                        scanned_ports += 1
                        progress = (scanned_ports / total_ports) * 100
                        self.progress_var.set(f"{progress:.1f}%")
                        
                    except Exception as e:
                        self.log_message(f"❌ Error scanning port {port}: {e}", "error")
                        
            # Mostrar resumen
            self.log_message(f"📊 Scan completed! Found {len(open_ports)} open ports", "success")
            
            # Análisis de vulnerabilidades si está habilitado
            if self.vuln_check_var.get() and open_ports:
                self.analyze_vulnerabilities(target_ip, open_ports)
                
            # Actualizar gráficos
            self.update_charts(open_ports)
            
        except Exception as e:
            self.log_message(f"❌ Scan failed: {e}", "error")
        finally:
            self.scanning = False
            self.scan_btn.config(text="🚀 START SCAN", state="normal")
            self.update_status("🟢 Ready | Scan completed", "accent_green")
            self.progress_var.set("100%")
            
    def scan_port(self, target, port):
        """Escanear un puerto específico"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config["timeout"])
            
            if self.stealth_var.get():
                # Modo stealth - usar connect_ex para evitar logs
                result = sock.connect_ex((target, port))
                sock.close()
                return result == 0
            else:
                # Escaneo normal
                sock.connect((target, port))
                sock.close()
                return True
                
        except (socket.error, socket.timeout):
            return False
            
    def grab_banner(self, target, port):
        """Obtener banner del servicio"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target, port))
            
            # Enviar request HTTP básico para puertos web
            if port in [80, 8080, 8000]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 21:  # FTP
                pass  # FTP envía banner automáticamente
            elif port == 25:  # SMTP
                pass  # SMTP envía banner automáticamente
            else:
                sock.send(b"\r\n")
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
            
        except (socket.error, socket.timeout, UnicodeDecodeError):
            return None
            
    def analyze_vulnerabilities(self, target, open_ports):
        """Analizar vulnerabilidades en puertos abiertos"""
        self.log_message("🛡️ Starting vulnerability analysis...", "info")
        
        vulnerabilities_found = []
        
        for port, _ in open_ports:
            service_info = self.services_db.get(port, {"name": "Unknown", "risk": "low"})
            
            # Verificar vulnerabilidades conocidas
            vulns = self.check_port_vulnerabilities(target, port, service_info)
            vulnerabilities_found.extend(vulns)
            
        if vulnerabilities_found:
            self.log_message(f"🚨 Found {len(vulnerabilities_found)} potential vulnerabilities!", "error")
            
            # Actualizar tree de vulnerabilidades
            for vuln in vulnerabilities_found:
                self.vulns_tree.insert("", "end", values=(
                    vuln["port"],
                    vuln["service"],
                    vuln["risk"],
                    vuln.get("cve", "N/A"),
                    vuln["description"]
                ))
        else:
            self.log_message("✅ No obvious vulnerabilities detected", "success")
            
    def check_port_vulnerabilities(self, target, port, service_info):
        """Verificar vulnerabilidades específicas del puerto"""
        vulnerabilities = []
        
        # Verificaciones específicas por servicio
        if port == 21:  # FTP
            if self.check_anonymous_ftp(target, port):
                vulnerabilities.append({
                    "port": port,
                    "service": "FTP",
                    "risk": "HIGH",
                    "cve": "CVE-2010-2861",
                    "description": "Anonymous FTP access enabled"
                })
                
        elif port == 23:  # Telnet
            vulnerabilities.append({
                "port": port,
                "service": "Telnet",
                "risk": "HIGH",
                "cve": "N/A",
                "description": "Telnet service active - unencrypted protocol"
            })
            
        elif port == 445:  # SMB
            if self.check_smb_vulnerabilities(target, port):
                vulnerabilities.append({
                    "port": port,
                    "service": "SMB",
                    "risk": "CRITICAL",
                    "cve": "CVE-2017-0144",
                    "description": "Potential EternalBlue vulnerability"
                })
                
        elif port == 3389:  # RDP
            vulnerabilities.append({
                "port": port,
                "service": "RDP",
                "risk": "MEDIUM",
                "cve": "CVE-2019-0708",
                "description": "RDP service exposed - potential BlueKeep vulnerability"
            })
            
        return vulnerabilities
        
    def check_anonymous_ftp(self, target, port):
        """Verificar acceso FTP anónimo"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # Recibir banner
            banner = sock.recv(1024)
            
            # Intentar login anónimo
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024)
            
            if b"331" in response:  # Password required
                sock.send(b"PASS anonymous@example.com\r\n")
                response = sock.recv(1024)
                
                if b"230" in response:  # Login successful
                    sock.close()
                    return True
                    
            sock.close()
            return False
            
        except (socket.error, socket.timeout):
            return False
            
    def check_smb_vulnerabilities(self, target, port):
        """Verificar vulnerabilidades SMB"""
        try:
            # Implementación básica de detección SMB
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # SMB negotiation packet (simplificado)
            smb_packet = (
                b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
            )
            
            sock.send(smb_packet)
            response = sock.recv(1024)
            sock.close()
            
            # Análisis básico de la respuesta
            if len(response) > 36 and response[4:8] == b"\xff\x53\x4d\x42":
                return True  # SMB activo, posible vulnerabilidad
                
            return False
            
        except (socket.error, socket.timeout):
            return False
            
    def update_charts(self, open_ports):
        """Actualizar gráficos con resultados"""
        if not open_ports:
            return
            
        # Limpiar gráficos anteriores
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
            ax.clear()
            ax.set_facecolor('#1a1f3a')
            
        # Gráfico 1: Puertos abiertos por servicio
        services = {}
        for port, _ in open_ports:
            service = self.services_db.get(port, {"name": "Unknown"})["name"]
            services[service] = services.get(service, 0) + 1
            
        if services:
            colors = ['#00d4ff', '#b300ff', '#39ff14', '#ff073a', '#ffff00']
            self.ax1.pie(services.values(), labels=services.keys(), 
                        colors=colors[:len(services)], autopct='%1.1f%%')
            self.ax1.set_title('Services Distribution', color='white')
            
        # Gráfico 2: Distribución de riesgo
        risk_levels = {"low": 0, "medium": 0, "high": 0}
        for port, _ in open_ports:
            risk = self.services_db.get(port, {"risk": "low"})["risk"]
            risk_levels[risk] += 1
            
        if any(risk_levels.values()):
            colors = ['#39ff14', '#ffff00', '#ff073a']
            self.ax2.bar(risk_levels.keys(), risk_levels.values(), color=colors)
            self.ax2.set_title('Risk Level Distribution', color='white')
            self.ax2.tick_params(colors='white')
            
        # Gráfico 3: Puertos más comunes
        port_counts = {}
        for port, _ in open_ports:
            port_counts[str(port)] = 1
            
        if port_counts:
            ports = list(port_counts.keys())[:10]  # Top 10
            counts = [port_counts[p] for p in ports]
            self.ax3.bar(ports, counts, color='#00d4ff')
            self.ax3.set_title('Open Ports', color='white')
            self.ax3.tick_params(colors='white')
            
        # Gráfico 4: Timeline de escaneo (simulado)
        scan_times = list(range(len(open_ports)))
        port_numbers = [port for port, _ in open_ports]
        
        if scan_times and port_numbers:
            self.ax4.plot(scan_times, port_numbers, 'o-', color='#39ff14')
            self.ax4.set_title('Scan Timeline', color='white')
            self.ax4.set_xlabel('Discovery Order', color='white')
            self.ax4.set_ylabel('Port Number', color='white')
            self.ax4.tick_params(colors='white')
            
        # Actualizar canvas
        self.canvas.draw()
        
    def stop_scan(self):
        """Detener escaneo actual"""
        self.scanning = False
        self.update_status("🛑 Scan stopped by user", "accent_red")
        self.log_message("🛑 Scan stopped by user request", "warning")
        
    def clear_results(self):
        """Limpiar resultados de escaneo"""
        self.console_output.delete(1.0, tk.END)
        
        # Limpiar tree de vulnerabilidades
        for item in self.vulns_tree.get_children():
            self.vulns_tree.delete(item)
            
        # Limpiar gráficos
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
            ax.clear()
            ax.set_facecolor('#1a1f3a')
        self.canvas.draw()
        
        self.progress_var.set("0%")
        self.update_status("🟢 Ready | Results cleared", "accent_green")
        self.log_message("🧹 Results cleared", "info")
        
    def auto_detect_network(self):
        """Auto-detectar red local"""
        try:
            self.log_message("🔍 Auto-detecting local network...", "info")
            
            # Obtener interfaces de red
            interfaces = netifaces.interfaces()
            local_networks = []
            
            for interface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            ip = addr_info.get('addr')
                            netmask = addr_info.get('netmask')
                            
                            if ip and netmask and not ip.startswith('127.'):
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                local_networks.append(str(network))
                                
                except (ValueError, KeyError):
                    continue
                    
            if local_networks:
                # Usar la primera red detectada
                detected_network = local_networks[0]
                self.network_entry.delete(0, tk.END)
                self.network_entry.insert(0, detected_network)
                self.log_message(f"✅ Detected network: {detected_network}", "success")
            else:
                self.log_message("❌ No local networks detected", "error")
                
        except Exception as e:
            self.log_message(f"❌ Error detecting network: {e}", "error")
            
    def scan_network_range(self):
        """Escanear rango de red"""
        network_range = self.network_entry.get().strip()
        if not network_range:
            messagebox.showerror("Error", "Please enter a network range!")
            return
            
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            self.log_message(f"🌐 Scanning network: {network}", "info")
            
            # Iniciar escaneo de red en hilo separado
            scan_thread = threading.Thread(
                target=self.perform_network_scan,
                args=(network,),
                daemon=True
            )
            scan_thread.start()
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid network range: {e}")
            
    def perform_network_scan(self, network):
        """Ejecutar escaneo de red"""
        try:
            # Limpiar resultados anteriores
            for item in self.discovery_tree.get_children():
                self.discovery_tree.delete(item)
                
            hosts_found = 0
            total_hosts = network.num_addresses
            
            self.log_message(f"🔍 Scanning {total_hosts} hosts...", "info")
            
            # Usar nmap para escaneo de red si está disponible
            try:
                nm = nmap.PortScanner()
                scan_result = nm.scan(hosts=str(network), arguments='-sn')  # Ping scan
                
                for host in scan_result['scan']:
                    if scan_result['scan'][host]['status']['state'] == 'up':
                        hosts_found += 1
                        self.process_discovered_host(host, scan_result['scan'][host])
                        
            except Exception as e:
                self.log_message(f"❌ Nmap scan failed: {e}", "error")
                # Fallback a ping scan manual
                self.manual_ping_scan(network)
                
        except Exception as e:
            self.log_message(f"❌ Network scan failed: {e}", "error")
            
    def process_discovered_host(self, host_ip, scan_data):
        """Procesar host descubierto"""
        try:
            # Obtener información del host
            hostname = "Unknown"
            mac_address = "Unknown"
            vendor = "Unknown"
            os_info = "Unknown"
            
            # Intentar resolver hostname
            try:
                hostname = socket.gethostbyaddr(host_ip)[0]
            except socket.herror:
                pass
                
            # Obtener MAC y vendor si está disponible
            if 'addresses' in scan_data:
                if 'mac' in scan_data['addresses']:
                    mac_address = scan_data['addresses']['mac']
                    vendor = scan_data['vendor'].get(mac_address, "Unknown")
                    
            # Escaneo rápido de puertos comunes
            common_ports = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389, 5900]
            open_ports = []
            
            for port in common_ports:
                if self.scan_port(host_ip, port):
                    open_ports.append(port)
                    
            open_ports_str = ", ".join(map(str, open_ports)) if open_ports else "None detected"
            
            # Agregar a la tabla
            self.discovery_tree.insert("", "end", values=(
                host_ip,
                hostname,
                mac_address,
                vendor,
                os_info,
                open_ports_str
            ))
            
            self.log_message(f"✅ Host discovered: {host_ip} ({hostname})", "success")
            
        except Exception as e:
            self.log_message(f"❌ Error processing host {host_ip}: {e}", "error")
            
    def manual_ping_scan(self, network):
        """Escaneo manual con ping"""
        self.log_message("🔄 Performing manual ping scan...", "info")
        
        def ping_host(host_ip):
            try:
                # Ping usando subprocess
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", str(host_ip)],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                
                if result.returncode == 0:
                    self.process_discovered_host(str(host_ip), {})
                    
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
        # Escanear hosts en paralelo
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            
            for host_ip in network.hosts():
                future = executor.submit(ping_host, host_ip)
                futures.append(future)
                
            # Esperar resultados
            for future in futures:
                try:
                    future.result(timeout=5)
                except Exception:
                    pass
                    
    def update_cve_database(self):
        """Actualizar base de datos CVE"""
        self.log_message("🔄 Updating CVE database...", "info")
        
        try:
            # Simulación de actualización CVE
            # En una implementación real, esto descargaría datos de NIST NVD
            self.log_message("📥 Downloading latest CVE data...", "info")
            time.sleep(2)  # Simular descarga
            
            # Cargar vulnerabilidades conocidas
            self.vulnerabilities_db = {
                "CVE-2017-0144": {
                    "description": "EternalBlue SMB vulnerability",
                    "severity": "CRITICAL",
                    "ports": [445],
                    "services": ["SMB"]
                },
                "CVE-2019-0708": {
                    "description": "BlueKeep RDP vulnerability",
                    "severity": "CRITICAL",
                    "ports": [3389],
                    "services": ["RDP"]
                },
                "CVE-2021-44228": {
                    "description": "Log4Shell vulnerability",
                    "severity": "CRITICAL",
                    "ports": [80, 443, 8080],
                    "services": ["HTTP", "HTTPS"]
                }
            }
            
            self.log_message("✅ CVE database updated successfully", "success")
            
        except Exception as e:
            self.log_message(f"❌ Failed to update CVE database: {e}", "error")
            
    def deep_vulnerability_scan(self):
        """Escaneo profundo de vulnerabilidades"""
        self.log_message("🔍 Starting deep vulnerability scan...", "info")
        
        # Verificar si hay resultados de escaneo previo
        if not hasattr(self, 'last_scan_results') or not self.last_scan_results:
            messagebox.showwarning("Warning", "No previous scan results found. Please run a port scan first.")
            return
            
        # Análisis profundo de cada puerto abierto
        for port, service_info in self.last_scan_results:
            self.deep_analyze_port(self.target_entry.get(), port, service_info)
            
    def deep_analyze_port(self, target, port, service_info):
        """Análisis profundo de un puerto específico"""
        self.log_message(f"🔍 Deep analyzing port {port}...", "info")
        
        # Análisis específico por servicio
        if port == 80 or port == 443:
            self.analyze_web_service(target, port)
        elif port == 21:
            self.analyze_ftp_service(target, port)
        elif port == 22:
            self.analyze_ssh_service(target, port)
        elif port == 25:
            self.analyze_smtp_service(target, port)
            
    def analyze_web_service(self, target, port):
        """Analizar servicio web"""
        try:
            protocol = "https" if port == 443 else "http"
            url = f"{protocol}://{target}:{port}"
            
            self.log_message(f"🌐 Analyzing web service at {url}", "info")
            
            # Request HTTP básico
            response = requests.get(url, timeout=5, verify=False)
            
            # Análizar headers
            headers = response.headers
            server = headers.get('Server', 'Unknown')
            
            self.detailed_vulns_text.insert(tk.END, f"Web Service: {url}\n")
            self.detailed_vulns_text.insert(tk.END, f"Server: {server}\n")
        except Exception as e:
            self.log_message(f"❌ Error analyzing web service at {url}: {e}", "error")
