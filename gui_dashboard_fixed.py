#!/usr/bin/env python3
"""
SIEM/SOAR Interactive Dashboard
Interfaz gráfica interactiva para mostrar el funcionamiento del sistema SIEM/SOAR
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import time
import json
import os
import csv
from datetime import datetime, timedelta
import subprocess
import sys

# Importar componentes del SIEM
try:
    from collector import LogCollector
    from parser import LogParser
    from correlator import EventCorrelator
    from orchestrator import SIEMOrchestrator
    from actions import ActionExecutor
except ImportError as e:
    print(f"Error importing SIEM modules: {e}")
    print("Make sure all SIEM modules are available")

class SIEMDashboard:
    """Dashboard interactivo para SIEM/SOAR"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛡️ SIEM/SOAR Security Dashboard - Universidad Distrital")
        self.root.geometry("1400x900")
        self.root.configure(bg="#1e1e1e")
        
        # Variables de control
        self.is_running = False
        self.siem_orchestrator = None
        self.update_queue = queue.Queue()
        
        # Contadores y estadísticas
        self.stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'actions_executed': 0,
            'uptime_start': None
        }
        
        # Crear interfaz
        self.create_widgets()
        self.setup_styles()
        
        # Iniciar hilo de actualización
        self.start_update_thread()
        
    def setup_styles(self):
        """Configurar estilos personalizados"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Estilo para frames principales
        style.configure('Dashboard.TFrame', background='#2d2d2d')
        style.configure('Header.TFrame', background='#1a472a')
        
        # Estilo para labels
        style.configure('Header.TLabel', 
                       background='#1a472a', 
                       foreground='white', 
                       font=('Arial', 12, 'bold'))
        
        style.configure('Status.TLabel', 
                       background='#2d2d2d', 
                       foreground='#00ff00', 
                       font=('Arial', 10, 'bold'))
        
        style.configure('Counter.TLabel', 
                       background='#2d2d2d', 
                       foreground='#ffff00', 
                       font=('Arial', 14, 'bold'))
        
    def create_widgets(self):
        """Crear widgets de la interfaz"""
        
        # Frame principal
        main_frame = ttk.Frame(self.root, style='Dashboard.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.create_header(main_frame)
        
        # Panel de control
        self.create_control_panel(main_frame)
        
        # Notebook para pestañas
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Crear pestañas
        self.create_monitoring_tab()
        self.create_events_tab()
        self.create_alerts_tab()
        self.create_actions_tab()
        self.create_config_tab()
        
    def create_header(self, parent):
        """Crear header con título y estado"""
        header_frame = ttk.Frame(parent, style='Header.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Título
        title_label = ttk.Label(header_frame, 
                               text="🛡️ SIEM/SOAR Security Dashboard", 
                               style='Header.TLabel')
        title_label.pack(side=tk.LEFT, padx=10, pady=10)
        
        # Estado del sistema
        self.status_label = ttk.Label(header_frame, 
                                     text="🔴 Sistema Detenido", 
                                     style='Status.TLabel')
        self.status_label.pack(side=tk.RIGHT, padx=10, pady=10)
        
    def create_control_panel(self, parent):
        """Crear panel de control principal"""
        control_frame = ttk.LabelFrame(parent, text="Control del Sistema", padding=10)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Botones de control
        self.start_button = tk.Button(control_frame, 
                                     text="▶️ Iniciar\nSIEM/SOAR",
                                     command=self.start_siem,
                                     bg="#2e7d32", fg="white",
                                     font=('Arial', 10, 'bold'),
                                     height=3, width=12)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(control_frame, 
                                    text="⏹️ Detener\nSIEM/SOAR",
                                    command=self.stop_siem,
                                    bg="#d32f2f", fg="white",
                                    font=('Arial', 10, 'bold'),
                                    height=3, width=12,
                                    state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Botón de test de ransomware
        self.test_ransomware_button = tk.Button(control_frame,
                                               text="🦠 Simular\nRansomware",
                                               command=self.simulate_ransomware,
                                               bg="#ff6f00", fg="white",
                                               font=('Arial', 10, 'bold'),
                                               height=3, width=12)
        self.test_ransomware_button.pack(side=tk.LEFT, padx=5)
        
        # Botón de test de fuerza bruta
        self.test_bruteforce_button = tk.Button(control_frame,
                                               text="🔨 Simular\nFuerza Bruta",
                                               command=self.simulate_bruteforce,
                                               bg="#7b1fa2", fg="white",
                                               font=('Arial', 10, 'bold'),
                                               height=3, width=12)
        self.test_bruteforce_button.pack(side=tk.LEFT, padx=5)
        
        # Estadísticas rápidas
        stats_frame = ttk.Frame(control_frame)
        stats_frame.pack(side=tk.RIGHT, padx=20)
        
        self.events_counter = ttk.Label(stats_frame, text="Eventos: 0", style='Counter.TLabel')
        self.events_counter.pack()
        
        self.alerts_counter = ttk.Label(stats_frame, text="Alertas: 0", style='Counter.TLabel')
        self.alerts_counter.pack()
        
        self.actions_counter = ttk.Label(stats_frame, text="Acciones: 0", style='Counter.TLabel')
        self.actions_counter.pack()
        
    def create_monitoring_tab(self):
        """Crear pestaña de monitoreo en tiempo real"""
        monitoring_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitoring_frame, text="📊 Monitoreo en Tiempo Real")
        
        # Panel de métricas
        metrics_frame = ttk.LabelFrame(monitoring_frame, text="Métricas del Sistema", padding=10)
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Métricas en columnas
        col1 = ttk.Frame(metrics_frame)
        col1.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        col2 = ttk.Frame(metrics_frame)
        col2.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        col3 = ttk.Frame(metrics_frame)
        col3.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        # Métricas columna 1
        ttk.Label(col1, text="📈 Eventos Procesados:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        self.events_metric = ttk.Label(col1, text="0", font=('Arial', 14))
        self.events_metric.pack(anchor=tk.W)
        
        ttk.Label(col1, text="⚠️ Alertas Generadas:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        self.alerts_metric = ttk.Label(col1, text="0", font=('Arial', 14))
        self.alerts_metric.pack(anchor=tk.W)
        
        # Métricas columna 2
        ttk.Label(col2, text="🤖 Acciones SOAR:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        self.actions_metric = ttk.Label(col2, text="0", font=('Arial', 14))
        self.actions_metric.pack(anchor=tk.W)
        
        ttk.Label(col2, text="🌐 Puerto Syslog:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        self.port_metric = ttk.Label(col2, text="5140", font=('Arial', 14))
        self.port_metric.pack(anchor=tk.W)
        
        # Métricas columna 3
        ttk.Label(col3, text="⏱️ Tiempo Activo:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        self.uptime_metric = ttk.Label(col3, text="00:00:00", font=('Arial', 14))
        self.uptime_metric.pack(anchor=tk.W)
        
        ttk.Label(col3, text="🔗 Estado Conexión:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        self.connection_metric = ttk.Label(col3, text="Desconectado", font=('Arial', 14))
        self.connection_metric.pack(anchor=tk.W)
        
        # Log de actividad en tiempo real
        activity_frame = ttk.LabelFrame(monitoring_frame, text="📝 Actividad en Tiempo Real", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.activity_log = scrolledtext.ScrolledText(activity_frame, 
                                                     height=15, 
                                                     bg="#000000", 
                                                     fg="#00ff00",
                                                     font=('Consolas', 10))
        self.activity_log.pack(fill=tk.BOTH, expand=True)
        
    def create_events_tab(self):
        """Crear pestaña de eventos"""
        events_frame = ttk.Frame(self.notebook)
        self.notebook.add(events_frame, text="📋 Eventos de Seguridad")
        
        # Filtros
        filter_frame = ttk.LabelFrame(events_frame, text="Filtros", padding=10)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Tipo de Evento:").pack(side=tk.LEFT)
        self.event_type_filter = ttk.Combobox(filter_frame, 
                                             values=["Todos", "authentication_failure", 
                                                    "authentication_success", "ransomware_detected",
                                                    "security_block", "connection", "error"])
        self.event_type_filter.set("Todos")
        self.event_type_filter.pack(side=tk.LEFT, padx=5)
        
        refresh_events_btn = tk.Button(filter_frame, text="🔄 Actualizar", 
                                      command=self.refresh_events,
                                      bg="#1976d2", fg="white")
        refresh_events_btn.pack(side=tk.LEFT, padx=10)
        
        # Tabla de eventos
        events_table_frame = ttk.Frame(events_frame)
        events_table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("Timestamp", "IP Origen", "Tipo", "Detalles")
        self.events_tree = ttk.Treeview(events_table_frame, columns=columns, show="headings", height=20)
        
        for col in columns:
            self.events_tree.heading(col, text=col)
            self.events_tree.column(col, width=150)
        
        # Scrollbar para la tabla
        events_scrollbar = ttk.Scrollbar(events_table_frame, orient=tk.VERTICAL, command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=events_scrollbar.set)
        
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        events_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_alerts_tab(self):
        """Crear pestaña de alertas"""
        alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(alerts_frame, text="🚨 Alertas de Seguridad")
        
        # Resumen de alertas
        summary_frame = ttk.LabelFrame(alerts_frame, text="📊 Resumen de Alertas", padding=10)
        summary_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Contadores por tipo de alerta
        counter_frame = ttk.Frame(summary_frame)
        counter_frame.pack(fill=tk.X)
        
        self.alert_counters = {}
        alert_types = ["R1_login_failures", "R2_off_hours_access", "R3_ransomware_detected"]
        colors = ["#ff5722", "#ff9800", "#f44336"]
        
        for i, (alert_type, color) in enumerate(zip(alert_types, colors)):
            frame = tk.Frame(counter_frame, bg=color, relief=tk.RAISED, bd=2)
            frame.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
            
            type_label = tk.Label(frame, text=alert_type.replace("_", " ").title(), 
                                 bg=color, fg="white", font=('Arial', 10, 'bold'))
            type_label.pack()
            
            counter_label = tk.Label(frame, text="0", bg=color, fg="white", 
                                   font=('Arial', 16, 'bold'))
            counter_label.pack()
            
            self.alert_counters[alert_type] = counter_label
        
        # Tabla de alertas
        alerts_table_frame = ttk.Frame(alerts_frame)
        alerts_table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        alert_columns = ("Timestamp", "Tipo", "Severidad", "IP", "Descripción")
        self.alerts_tree = ttk.Treeview(alerts_table_frame, columns=alert_columns, show="headings", height=15)
        
        for col in alert_columns:
            self.alerts_tree.heading(col, text=col)
            if col == "Descripción":
                self.alerts_tree.column(col, width=300)
            else:
                self.alerts_tree.column(col, width=120)
        
        alerts_scrollbar = ttk.Scrollbar(alerts_table_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_scrollbar.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alerts_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Botón para limpiar alertas
        clear_alerts_btn = tk.Button(alerts_frame, text="🗑️ Limpiar Alertas", 
                                    command=self.clear_alerts,
                                    bg="#d32f2f", fg="white")
        clear_alerts_btn.pack(pady=5)
        
    def create_actions_tab(self):
        """Crear pestaña de acciones SOAR"""
        actions_frame = ttk.Frame(self.notebook)
        self.notebook.add(actions_frame, text="🤖 Acciones SOAR")
        
        # Panel de acciones manuales
        manual_frame = ttk.LabelFrame(actions_frame, text="🎮 Acciones Manuales", padding=10)
        manual_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Campo para IP
        ttk.Label(manual_frame, text="IP Address:").pack(side=tk.LEFT)
        self.manual_ip_entry = tk.Entry(manual_frame, width=15)
        self.manual_ip_entry.pack(side=tk.LEFT, padx=5)
        self.manual_ip_entry.insert(0, "192.168.1.100")
        
        # Botones de acción manual
        isolate_btn = tk.Button(manual_frame, text="🔒 Aislar Host", 
                               command=self.manual_isolate_host,
                               bg="#e65100", fg="white")
        isolate_btn.pack(side=tk.LEFT, padx=5)
        
        # Campo para usuario
        ttk.Label(manual_frame, text="Usuario:").pack(side=tk.LEFT, padx=(20, 0))
        self.manual_user_entry = tk.Entry(manual_frame, width=15)
        self.manual_user_entry.pack(side=tk.LEFT, padx=5)
        self.manual_user_entry.insert(0, "admin")
        
        block_account_btn = tk.Button(manual_frame, text="🚫 Bloquear Cuenta", 
                                     command=self.manual_block_account,
                                     bg="#d32f2f", fg="white")
        block_account_btn.pack(side=tk.LEFT, padx=5)
        
        # Historial de acciones
        history_frame = ttk.LabelFrame(actions_frame, text="📜 Historial de Acciones", padding=10)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        action_columns = ("Timestamp", "Tipo", "Objetivo", "Estado", "Detalles")
        self.actions_tree = ttk.Treeview(history_frame, columns=action_columns, show="headings", height=18)
        
        for col in action_columns:
            self.actions_tree.heading(col, text=col)
            self.actions_tree.column(col, width=120)
        
        actions_scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.actions_tree.yview)
        self.actions_tree.configure(yscrollcommand=actions_scrollbar.set)
        
        self.actions_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        actions_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_config_tab(self):
        """Crear pestaña de configuración"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="⚙️ Configuración")
        
        # Configuración del sistema
        system_config_frame = ttk.LabelFrame(config_frame, text="🔧 Configuración del Sistema", padding=10)
        system_config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Puerto syslog
        ttk.Label(system_config_frame, text="Puerto Syslog:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.syslog_port_var = tk.StringVar(value="5140")
        syslog_port_entry = tk.Entry(system_config_frame, textvariable=self.syslog_port_var, width=10)
        syslog_port_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Intervalo de pipeline
        ttk.Label(system_config_frame, text="Intervalo Pipeline (seg):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.pipeline_interval_var = tk.StringVar(value="15")
        pipeline_interval_entry = tk.Entry(system_config_frame, textvariable=self.pipeline_interval_var, width=10)
        pipeline_interval_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Botón aplicar configuración
        apply_config_btn = tk.Button(system_config_frame, text="✅ Aplicar Configuración",
                                    command=self.apply_config,
                                    bg="#2e7d32", fg="white")
        apply_config_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Panel de comandos útiles
        commands_frame = ttk.LabelFrame(config_frame, text="💻 Comandos Útiles", padding=10)
        commands_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        commands_text = scrolledtext.ScrolledText(commands_frame, height=15, bg="#f5f5f5")
        commands_text.pack(fill=tk.BOTH, expand=True)
        
        useful_commands = """
# Comandos útiles para testing del SIEM/SOAR

# 1. Enviar mensaje syslog de prueba (requiere netcat)
echo "Test syslog message from 192.168.1.100" | nc -u localhost 5140

# 2. Enviar mensaje con PowerShell (Windows nativo)
$UdpClient = New-Object System.Net.Sockets.UdpClient
$UdpClient.Connect("localhost", 5140)
$Bytes = [System.Text.Encoding]::UTF8.GetBytes("Failed login for admin from 192.168.1.50")
$UdpClient.Send($Bytes, $Bytes.Length)
$UdpClient.Close()

# 3. Usar script de prueba incluido
python test_syslog.py

# 4. Ejecutar tests automatizados
python -m pytest test_pipeline.py -v

# 5. Ver logs en tiempo real
Get-Content test_logs\\raw.log -Wait -Tail 10

# 6. Ver alertas generadas
Get-Content alerts\\alerts.log -Tail 20

# 7. Ejecutar componentes individuales
python collector.py
python parser.py
python correlator.py
python orchestrator.py

# 8. Simular eventos de ransomware
# (Añadir a test_logs/raw.log):
# {"timestamp": "2023-10-15T14:31:15.789012", "source_ip": "192.168.1.50", "event_type": "ransomware_detected", "details": "File encryption detected"}

# 9. Limpiar logs y alertas
Remove-Item test_logs\\raw.log -ErrorAction SilentlyContinue
Remove-Item alerts\\alerts.log -ErrorAction SilentlyContinue

# 10. Ver estado de puertos
netstat -an | findstr :5140
        """
        
        commands_text.insert(tk.END, useful_commands)
        commands_text.config(state=tk.DISABLED)
        
    def start_siem(self):
        """Iniciar el sistema SIEM/SOAR"""
        try:
            self.log_activity("🚀 Iniciando sistema SIEM/SOAR...")
            
            # Crear configuración
            config = {
                'loop_interval': int(self.pipeline_interval_var.get()),
                'syslog_port': int(self.syslog_port_var.get())
            }
            
            # Inicializar orquestador
            self.siem_orchestrator = SIEMOrchestrator(config)
            
            # Iniciar syslog listener
            self.siem_orchestrator.start_syslog_collection(port=config['syslog_port'])
            
            # Iniciar pipeline en hilo separado
            self.siem_thread = threading.Thread(target=self.run_siem_pipeline, daemon=True)
            self.siem_thread.start()
            
            # Actualizar UI
            self.is_running = True
            self.stats['uptime_start'] = datetime.now()
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_label.config(text="🟢 Sistema Activo")
            self.connection_metric.config(text="Conectado")
            
            self.log_activity(f"✅ Sistema iniciado en puerto {config['syslog_port']}")
            self.log_activity(f"🔄 Pipeline ejecutándose cada {config['loop_interval']} segundos")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error iniciando SIEM: {e}")
            self.log_activity(f"❌ Error: {e}")
            
    def stop_siem(self):
        """Detener el sistema SIEM/SOAR"""
        try:
            self.log_activity("⏹️ Deteniendo sistema SIEM/SOAR...")
            
            self.is_running = False
            
            if self.siem_orchestrator:
                self.siem_orchestrator.stop_orchestrator()
                
            # Actualizar UI
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_label.config(text="🔴 Sistema Detenido")
            self.connection_metric.config(text="Desconectado")
            
            self.log_activity("✅ Sistema detenido correctamente")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error deteniendo SIEM: {e}")
            self.log_activity(f"❌ Error: {e}")
            
    def run_siem_pipeline(self):
        """Ejecutar pipeline SIEM en bucle"""
        while self.is_running:
            try:
                if self.siem_orchestrator:
                    # Ejecutar una iteración del pipeline
                    self.siem_orchestrator.run_single_iteration()
                    
                    # Actualizar estadísticas
                    self.update_stats()
                    
                time.sleep(int(self.pipeline_interval_var.get()))
                
            except Exception as e:
                self.log_activity(f"❌ Error en pipeline: {e}")
                time.sleep(5)
                
    def simulate_ransomware(self):
        """Simular ataque de ransomware"""
        try:
            self.log_activity("🦠 Simulando ataque de ransomware...")
            
            # Crear eventos de ransomware simulados
            ransomware_events = [
                '{"timestamp": "' + datetime.now().isoformat() + '", "source_ip": "192.168.1.66", "event_type": "ransomware_detected", "details": "File encryption activity detected on C:\\\\Users\\\\Documents\\\\*.docx", "extra_process": "malware_encrypt.exe", "extra_files_affected": 156}',
                datetime.now().isoformat() + ' [192.168.1.66] Oct 22 ' + datetime.now().strftime('%H:%M:%S') + ' server malware: RANSOMWARE ACTIVITY DETECTED - URGENT',
                datetime.now().isoformat() + ' [192.168.1.66] Oct 22 ' + datetime.now().strftime('%H:%M:%S') + ' server security: File encryption process started by unknown executable'
            ]
            
            # Escribir eventos al archivo raw.log
            raw_log_path = os.path.join("test_logs", "raw.log")
            os.makedirs("test_logs", exist_ok=True)
            
            with open(raw_log_path, 'a', encoding='utf-8') as f:
                for event in ransomware_events:
                    f.write(event + '\n')
                    
            self.log_activity("🦠 Eventos de ransomware simulados - El sistema debería detectar y responder automáticamente")
            
            # Forzar actualización inmediata de estadísticas
            self.update_stats()
            
            # Mostrar información del ataque
            messagebox.showinfo("Simulación Ransomware", 
                              "🦠 Ataque de ransomware simulado!\n\n"
                              "IP Atacante: 192.168.1.66\n"
                              "Archivos afectados: 156\n"
                              "Proceso malicioso: malware_encrypt.exe\n\n"
                              "El sistema SIEM debería detectar automáticamente este ataque "
                              "y ejecutar acciones de respuesta como aislamiento del host.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error simulando ransomware: {e}")
            self.log_activity(f"❌ Error: {e}")
            
    def simulate_bruteforce(self):
        """Simular ataque de fuerza bruta"""
        try:
            self.log_activity("🔨 Simulando ataque de fuerza bruta...")
            
            # Crear 6 eventos de login fallido desde la misma IP
            bruteforce_events = []
            base_time = datetime.now()
            
            for i in range(6):
                event_time = (base_time + timedelta(seconds=i*30)).isoformat()
                event = f"{event_time} [192.168.1.88] Oct 22 {(base_time + timedelta(seconds=i*30)).strftime('%H:%M:%S')} server sshd: Failed password for user admin from 192.168.1.88"
                bruteforce_events.append(event)
                
            # Escribir eventos al archivo raw.log
            raw_log_path = os.path.join("test_logs", "raw.log")
            os.makedirs("test_logs", exist_ok=True)
            
            with open(raw_log_path, 'a', encoding='utf-8') as f:
                for event in bruteforce_events:
                    f.write(event + '\n')
                    
            self.log_activity("🔨 Ataque de fuerza bruta simulado - 6 intentos fallidos desde 192.168.1.88")
            
            # Forzar actualización inmediata de estadísticas
            self.update_stats()
            
            # Mostrar información del ataque
            messagebox.showinfo("Simulación Fuerza Bruta", 
                              "🔨 Ataque de fuerza bruta simulado!\n\n"
                              "IP Atacante: 192.168.1.88\n"
                              "Intentos fallidos: 6\n"
                              "Usuario objetivo: admin\n"
                              "Ventana de tiempo: 5 minutos\n\n"
                              "El sistema SIEM debería detectar este patrón "
                              "y generar una alerta de seguridad.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error simulando fuerza bruta: {e}")
            self.log_activity(f"❌ Error: {e}")
            
    def manual_isolate_host(self):
        """Aislar host manualmente"""
        ip = self.manual_ip_entry.get().strip()
        if ip:
            try:
                if hasattr(self, 'siem_orchestrator') and self.siem_orchestrator:
                    success = self.siem_orchestrator.action_executor.isolate_host(ip)
                    if success:
                        self.log_activity(f"🔒 Host {ip} aislado manualmente")
                        self.update_actions_display()
                        self.update_stats()
                    else:
                        self.log_activity(f"❌ Error aislando host {ip}")
                else:
                    self.log_activity("⚠️ Sistema SIEM no está iniciado")
            except Exception as e:
                self.log_activity(f"❌ Error: {e}")
        else:
            messagebox.showwarning("Advertencia", "Ingrese una dirección IP válida")
            
    def manual_block_account(self):
        """Bloquear cuenta manualmente"""
        user = self.manual_user_entry.get().strip()
        if user:
            try:
                if hasattr(self, 'siem_orchestrator') and self.siem_orchestrator:
                    success = self.siem_orchestrator.action_executor.block_account(user)
                    if success:
                        self.log_activity(f"🚫 Cuenta {user} bloqueada manualmente")
                        self.update_actions_display()
                        self.update_stats()
                    else:
                        self.log_activity(f"❌ Error bloqueando cuenta {user}")
                else:
                    self.log_activity("⚠️ Sistema SIEM no está iniciado")
            except Exception as e:
                self.log_activity(f"❌ Error: {e}")
        else:
            messagebox.showwarning("Advertencia", "Ingrese un nombre de usuario válido")
            
    def refresh_events(self):
        """Actualizar tabla de eventos"""
        try:
            # Limpiar tabla actual
            for item in self.events_tree.get_children():
                self.events_tree.delete(item)
                
            # Leer eventos desde raw.log
            raw_log_path = os.path.join("test_logs", "raw.log")
            if os.path.exists(raw_log_path):
                with open(raw_log_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                # Parsear eventos recientes (últimos 100)
                for line in lines[-100:]:
                    try:
                        # Parsear línea simple
                        if '[' in line and ']' in line:
                            parts = line.strip().split(' ', 2)
                            if len(parts) >= 3:
                                timestamp = parts[0]
                                ip_part = parts[1]
                                if ip_part.startswith('[') and ip_part.endswith(']'):
                                    source_ip = ip_part[1:-1]
                                    details = parts[2] if len(parts) > 2 else ""
                                    
                                    # Detectar tipo de evento básico
                                    event_type = "info"
                                    if "failed" in details.lower() or "invalid" in details.lower():
                                        event_type = "authentication_failure"
                                    elif "successful" in details.lower() and "login" in details.lower():
                                        event_type = "authentication_success"
                                    elif "ransomware" in details.lower():
                                        event_type = "ransomware_detected"
                                    elif "blocked" in details.lower() or "firewall" in details.lower():
                                        event_type = "security_block"
                                    
                                    # Filtrar si es necesario
                                    filter_type = self.event_type_filter.get()
                                    if filter_type == "Todos" or filter_type == event_type:
                                        self.events_tree.insert("", "end", values=(
                                            timestamp[:19],  # Timestamp corto
                                            source_ip,
                                            event_type,
                                            details[:80] + "..." if len(details) > 80 else details
                                        ))
                        # Parsear líneas JSON
                        elif line.strip().startswith('{'):
                            try:
                                event_data = json.loads(line.strip())
                                timestamp = event_data.get('timestamp', '')
                                source_ip = event_data.get('source_ip', '')
                                event_type = event_data.get('event_type', 'unknown')
                                details = event_data.get('details', '')
                                
                                # Filtrar si es necesario
                                filter_type = self.event_type_filter.get()
                                if filter_type == "Todos" or filter_type == event_type:
                                    self.events_tree.insert("", "end", values=(
                                        timestamp[:19],  # Timestamp corto
                                        source_ip,
                                        event_type,
                                        details[:80] + "..." if len(details) > 80 else details
                                    ))
                            except json.JSONDecodeError:
                                continue
                    except:
                        continue
                        
            self.log_activity("🔄 Tabla de eventos actualizada")
            
        except Exception as e:
            self.log_activity(f"❌ Error actualizando eventos: {e}")
            
    def refresh_alerts_display(self):
        """Actualizar display de alertas"""
        try:
            # Limpiar tabla de alertas
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
                
            # Reset contadores
            alert_counts = {"R1_login_failures": 0, "R2_off_hours_access": 0, "R3_ransomware_detected": 0}
            
            # Leer alertas desde archivo
            alerts_file = os.path.join("alerts", "alerts.log")
            if os.path.exists(alerts_file):
                try:
                    with open(alerts_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        
                    for line in lines[1:]:  # Skip header
                        if line.strip():
                            try:
                                parts = line.strip().split(',')
                                if len(parts) >= 3:
                                    rule_type = parts[0]
                                    timestamp = parts[1]
                                    ip = parts[2]
                                    
                                    # Contar por tipo
                                    if rule_type in alert_counts:
                                        alert_counts[rule_type] += 1
                                    
                                    # Determinar severidad
                                    severity = "INFO"
                                    if "R1" in rule_type:
                                        severity = "ALTA"
                                    elif "R2" in rule_type:
                                        severity = "MEDIA"
                                    elif "R3" in rule_type:
                                        severity = "CRÍTICA"
                                    
                                    # Añadir a tabla
                                    self.alerts_tree.insert("", "end", values=(
                                        timestamp[:19],
                                        rule_type,
                                        severity,
                                        ip,
                                        f"Alerta generada por {rule_type}"
                                    ))
                            except:
                                continue
                except:
                    pass
            
            # Actualizar contadores visuales
            for alert_type, count in alert_counts.items():
                if alert_type in self.alert_counters:
                    self.alert_counters[alert_type].config(text=str(count))
                    
        except Exception as e:
            self.log_activity(f"❌ Error actualizando alertas: {e}")
            
    def clear_alerts(self):
        """Limpiar alertas"""
        try:
            # Limpiar tabla de alertas
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
                
            # Reset contadores
            for counter in self.alert_counters.values():
                counter.config(text="0")
                
            # Limpiar archivo de alertas
            alerts_file = os.path.join("alerts", "alerts.log")
            if os.path.exists(alerts_file):
                with open(alerts_file, 'w', encoding='utf-8') as f:
                    f.write("rule,timestamp,ip\n")  # Escribir solo header
                
            self.log_activity("🗑️ Alertas limpiadas")
            self.update_stats()
            
        except Exception as e:
            self.log_activity(f"❌ Error limpiando alertas: {e}")
            
    def apply_config(self):
        """Aplicar configuración"""
        try:
            port = int(self.syslog_port_var.get())
            interval = int(self.pipeline_interval_var.get())
            
            if port < 1024 or port > 65535:
                messagebox.showerror("Error", "Puerto debe estar entre 1024 y 65535")
                return
                
            if interval < 5 or interval > 300:
                messagebox.showerror("Error", "Intervalo debe estar entre 5 y 300 segundos")
                return
                
            self.log_activity(f"⚙️ Configuración aplicada - Puerto: {port}, Intervalo: {interval}s")
            
            if self.is_running:
                messagebox.showinfo("Información", 
                                   "Configuración guardada. Reinicie el sistema para aplicar cambios.")
            else:
                messagebox.showinfo("Información", "Configuración aplicada correctamente.")
                
        except ValueError:
            messagebox.showerror("Error", "Valores de configuración inválidos")
            
    def update_stats(self):
        """Actualizar estadísticas del sistema"""
        try:
            # Contar eventos procesados
            events_count = 0
            raw_log_path = os.path.join("test_logs", "raw.log")
            if os.path.exists(raw_log_path):
                try:
                    with open(raw_log_path, 'r', encoding='utf-8') as f:
                        events_count = len([line for line in f.readlines() if line.strip()])
                except Exception:
                    events_count = 0
                    
            # Contar alertas
            alerts_count = 0
            alerts_file = os.path.join("alerts", "alerts.log")
            if os.path.exists(alerts_file):
                try:
                    with open(alerts_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        # Solo contar líneas que no sean header y que tengan contenido
                        alerts_count = max(0, len([line for line in lines if line.strip() and not line.startswith('rule,timestamp,ip')]))
                except Exception:
                    alerts_count = 0
                    
            # Contar acciones
            actions_count = 0
            if hasattr(self, 'siem_orchestrator') and self.siem_orchestrator and hasattr(self.siem_orchestrator, 'action_executor'):
                try:
                    actions_count = len(self.siem_orchestrator.action_executor.action_log)
                except Exception:
                    actions_count = 0
                
            # Actualizar contadores en UI
            self.stats['events_processed'] = events_count
            self.stats['alerts_generated'] = alerts_count
            self.stats['actions_executed'] = actions_count
            
            # Poner en cola la actualización de UI
            self.update_queue.put(('stats', {
                'events': events_count,
                'alerts': alerts_count,
                'actions': actions_count
            }))
            
            # También actualizar las tablas de alertas y acciones si están visibles
            self.update_queue.put(('refresh_alerts', None))
            
        except Exception as e:
            self.log_activity(f"❌ Error actualizando estadísticas: {e}")
            # En caso de error, al menos mostrar los contadores básicos
            self.update_queue.put(('stats', {
                'events': self.stats.get('events_processed', 0),
                'alerts': self.stats.get('alerts_generated', 0),
                'actions': self.stats.get('actions_executed', 0)
            }))
            
    def update_actions_display(self):
        """Actualizar display de acciones"""
        try:
            # Limpiar tabla
            for item in self.actions_tree.get_children():
                self.actions_tree.delete(item)
                
            # Obtener historial de acciones
            if hasattr(self, 'siem_orchestrator') and self.siem_orchestrator and hasattr(self.siem_orchestrator, 'action_executor'):
                actions = self.siem_orchestrator.action_executor.get_action_history()
                
                # Mostrar últimas 50 acciones
                for action in actions[-50:]:
                    self.actions_tree.insert("", "end", values=(
                        action.get('timestamp', '')[:19],
                        action.get('action_type', ''),
                        action.get('target', ''),
                        action.get('status', ''),
                        action.get('details', '')[:50] if action.get('details') else ''
                    ))
                    
        except Exception as e:
            self.log_activity(f"❌ Error actualizando acciones: {e}")
            
    def start_update_thread(self):
        """Iniciar hilo de actualización de UI"""
        def update_ui():
            while True:
                try:
                    # Procesar actualizaciones en cola
                    while not self.update_queue.empty():
                        try:
                            update_type, data = self.update_queue.get_nowait()
                            
                            if update_type == 'stats':
                                self.events_counter.config(text=f"Eventos: {data['events']}")
                                self.alerts_counter.config(text=f"Alertas: {data['alerts']}")
                                self.actions_counter.config(text=f"Acciones: {data['actions']}")
                                
                                self.events_metric.config(text=str(data['events']))
                                self.alerts_metric.config(text=str(data['alerts']))
                                self.actions_metric.config(text=str(data['actions']))
                                
                            elif update_type == 'activity':
                                self.activity_log.insert(tk.END, data + '\n')
                                self.activity_log.see(tk.END)
                                
                            elif update_type == 'refresh_alerts':
                                try:
                                    self.refresh_alerts_display()
                                except:
                                    pass
                        except queue.Empty:
                            break
                        except Exception:
                            continue
                            
                    # Actualizar tiempo activo
                    if self.is_running and self.stats['uptime_start']:
                        uptime = datetime.now() - self.stats['uptime_start']
                        uptime_str = str(uptime).split('.')[0]  # Remover microsegundos
                        self.uptime_metric.config(text=uptime_str)
                        
                    time.sleep(1)
                    
                except Exception:
                    time.sleep(1)
                    
        update_thread = threading.Thread(target=update_ui, daemon=True)
        update_thread.start()
        
    def log_activity(self, message):
        """Registrar actividad en el log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        # Poner en cola para actualización de UI
        self.update_queue.put(('activity', formatted_message))
        
        # También imprimir en consola
        print(formatted_message)
        
    def run(self):
        """Ejecutar la aplicación"""
        # Mostrar mensaje de bienvenida
        self.log_activity("🛡️ Dashboard SIEM/SOAR iniciado")
        self.log_activity("📚 Universidad Distrital Francisco José de Caldas")
        self.log_activity("🎓 Redes de Comunicación 3 - Taller 2")
        self.log_activity("👨‍🎓 Desarrollado por: David Alejandro Colorado Rodríguez")
        self.log_activity("")
        self.log_activity("ℹ️ Funcionalidades disponibles:")
        self.log_activity("  • Recolección de logs via syslog UDP")
        self.log_activity("  • Análisis y correlación de eventos de seguridad")
        self.log_activity("  • Detección de ataques (fuerza bruta, ransomware, accesos fuera de horario)")
        self.log_activity("  • Respuestas automáticas SOAR (aislamiento, bloqueo, notificaciones)")
        self.log_activity("  • Simulación de ataques para testing")
        self.log_activity("")
        self.log_activity("🚀 Para comenzar, haga clic en 'Iniciar SIEM/SOAR'")
        
        # Iniciar bucle principal
        self.root.mainloop()

def main():
    """Función principal"""
    try:
        # Verificar que estamos en el directorio correcto
        required_files = ['collector.py', 'parser.py', 'correlator.py', 'orchestrator.py', 'actions.py']
        missing_files = [f for f in required_files if not os.path.exists(f)]
        
        if missing_files:
            print("❌ Error: No se encontraron los siguientes archivos del SIEM:")
            for file in missing_files:
                print(f"  - {file}")
            print("\n💡 Asegúrese de ejecutar este script desde el directorio siem_soar/")
            return
            
        # Crear directorios necesarios
        os.makedirs("test_logs", exist_ok=True)
        os.makedirs("alerts", exist_ok=True)
        
        # Crear archivo raw.log con algunos eventos de ejemplo si no existe
        raw_log_path = os.path.join("test_logs", "raw.log")
        if not os.path.exists(raw_log_path):
            with open(raw_log_path, 'w', encoding='utf-8') as f:
                sample_events = [
                    f"{datetime.now().isoformat()} [192.168.1.50] Oct 22 14:30:15 server sshd: Failed password for user admin",
                    f"{datetime.now().isoformat()} [192.168.1.100] Oct 22 14:31:00 server login: User john logged in successfully",
                    f"{datetime.now().isoformat()} [192.168.1.200] Oct 22 14:32:00 firewall: Connection blocked from suspicious IP",
                ]
                for event in sample_events:
                    f.write(event + '\n')
        
        # Crear archivo de alertas con header si no existe
        alerts_file = os.path.join("alerts", "alerts.log")
        if not os.path.exists(alerts_file):
            with open(alerts_file, 'w', encoding='utf-8') as f:
                f.write("rule,timestamp,ip\n")
        
        # Inicializar y ejecutar dashboard
        print("🚀 Iniciando Dashboard SIEM/SOAR...")
        dashboard = SIEMDashboard()
        dashboard.run()
        
    except KeyboardInterrupt:
        print("\n👋 Dashboard cerrado por el usuario")
    except Exception as e:
        print(f"❌ Error crítico: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
