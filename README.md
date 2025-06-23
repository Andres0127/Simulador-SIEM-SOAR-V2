# SIEM/SOAR Security Platform

Un sistema básico de SIEM (Security Information and Event Management) y SOAR (Security Orchestration, Automation and Response) desarrollado en Python para el Taller 2 de Redes de Comunicación 3.

## ✅ ESTADO DEL PROYECTO: COMPLETAMENTE FUNCIONAL

**🎉 IMPLEMENTACIÓN EXITOSA - TODOS LOS COMPONENTES FUNCIONANDO**

- ✅ **16/16 pruebas automatizadas PASANDO**
- ✅ **Detección de ransomware funcionando**
- ✅ **Detección de ataques de fuerza bruta funcionando**
- ✅ **Acciones SOAR automáticas funcionando**
- ✅ **Pipeline end-to-end funcionando**
- ✅ **Generación de alertas en CSV funcionando**
- ✅ **Listener syslog funcionando**
- ✅ **🆕 DASHBOARD GRÁFICO INTERACTIVO IMPLEMENTADO**

## 🆕 NUEVA CARACTERÍSTICA: Dashboard Gráfico Interactivo

### 🚀 Ejecutar el Dashboard Gráfico
```bash
# Iniciar la interfaz gráfica interactiva
python gui_dashboard.py
```

**Características del Dashboard:**
- 🎛️ **Control Total**: Iniciar/detener sistema SIEM/SOAR con un clic
- 📊 **Monitoreo en Tiempo Real**: Métricas y estadísticas actualizándose automáticamente
- 🧪 **Simulación de Ataques**: Botones para simular ransomware y fuerza bruta
- 📋 **Gestión de Eventos**: Tabla filtrable de eventos de seguridad
- 🚨 **Panel de Alertas**: Visualización de alertas por tipo y severidad
- 🤖 **Control SOAR**: Ejecución manual de acciones de respuesta
- ⚙️ **Configuración**: Ajuste de puertos y intervalos
- 📝 **Log en Tiempo Real**: Stream de actividad del sistema

### 📸 Funcionalidades del Dashboard

1. **Panel de Control Principal**
   - Iniciar/detener sistema completo
   - Contadores en tiempo real (eventos, alertas, acciones)
   - Simulación de ataques con un clic

2. **Pestaña: Monitoreo en Tiempo Real**
   - Métricas del sistema actualizándose automáticamente
   - Log de actividad con colores para fácil lectura
   - Estado de conexión y tiempo activo

3. **Pestaña: Eventos de Seguridad**
   - Tabla completa de eventos recolectados
   - Filtros por tipo de evento
   - Actualización automática

4. **Pestaña: Alertas de Seguridad**
   - Resumen visual por tipo de alerta (R1, R2, R3)
   - Tabla detallada de alertas generadas
   - Opción para limpiar alertas

5. **Pestaña: Acciones SOAR**
   - Ejecución manual de acciones (aislar host, bloquear cuenta)
   - Historial completo de acciones automáticas y manuales

6. **Pestaña: Configuración**
   - Ajuste de puerto syslog y intervalo del pipeline
   - Lista de comandos útiles para testing

### 🎯 Flujo de Uso Recomendado

1. **Iniciar**: `python gui_dashboard.py`
2. **Configurar**: Verificar puerto (5140) e intervalo (15s) en pestaña Configuración
3. **Activar**: Hacer clic en "▶️ Iniciar SIEM/SOAR"
4. **Probar**: Usar botones "🦠 Simular Ransomware" o "🔨 Simular Fuerza Bruta"
5. **Monitorear**: Observar detección automática y respuestas SOAR
6. **Analizar**: Revisar eventos, alertas y acciones en pestañas correspondientes

## Estructura del Proyecto

```
siem_soar/
├── collector.py      # Recolección de logs de seguridad
├── parser.py         # Análisis y normalización de eventos
├── correlator.py     # Motor de correlación de eventos
├── orchestrator.py   # Orquestador principal del sistema
├── actions.py        # Acciones automatizadas de respuesta
├── test_logs/        # Directorio para logs de prueba
│   └── raw.log       # Logs recolectados por el collector
├── alerts/           # Directorio para alertas generadas
│   └── alerts.log    # Alertas en formato CSV
├── test_pipeline.py  # Tests automatizados con pytest
├── requirements.txt  # Dependencias del proyecto
└── README.md         # Documentación del proyecto
```

## Instalación y Configuración

### 1. Preparación del Entorno

```bash
# Navegar al directorio del proyecto
cd "c:\Users\DavidAColoradoR\OneDrive - Universidad Distrital Francisco José de Caldas\Universidad\NovenoSemestre\RedesDeComunicacion3\Taller2\siem_soar"

# Crear entorno virtual (recomendado)
python -m venv venv

# Activar entorno virtual
# En Windows:
venv\Scripts\activate
# En Linux/Mac:
# source venv/bin/activate
```

### 2. Instalación de Dependencias

```bash
# Instalar todas las dependencias requeridas
pip install -r requirements.txt
```

Las dependencias principales incluyen:
- `python-dotenv`: Gestión de variables de entorno
- `pytest`: Framework de testing
- `pytest-cov`: Cobertura de tests
- `requests`: Cliente HTTP
- `python-dateutil`: Utilidades de fecha/hora
- `psutil`: Información del sistema
- `cryptography`: Funciones criptográficas
- `pyyaml`: Parser YAML

### 3. Verificación de la Instalación

```bash
# Ejecutar tests para verificar que todo funciona
python -m pytest test_pipeline.py -v
```

## Ejecución del Sistema

### Inicio del Pipeline Completo

```bash
# Ejecutar el orquestador principal
python orchestrator.py
```

**Salida esperada:**
```
Starting SIEM/SOAR Orchestrator
================================
Syslog listener will start on port 5140
Pipeline will run every 15 seconds
Press Ctrl+C to stop

2023-10-15 14:30:00,123 - collector - INFO - Syslog listener started on 0.0.0.0:5140
2023-10-15 14:30:00,124 - orchestrator - INFO - Starting end-to-end SIEM/SOAR flow
2023-10-15 14:30:00,125 - orchestrator - INFO - Starting iteration 1
2023-10-15 14:30:00,126 - orchestrator - INFO - Step 1: Parsing raw logs
2023-10-15 14:30:00,127 - parser - INFO - Parsed 11 events from test_logs\raw.log
2023-10-15 14:30:00,128 - orchestrator - INFO - Parsed 11 events
2023-10-15 14:30:00,129 - orchestrator - INFO - Step 2: Running correlation analysis
2023-10-15 14:30:00,130 - correlator - CRITICAL - RANSOMWARE DETECTED from 192.168.1.50!
2023-10-15 14:30:00,131 - correlator - CRITICAL - R3 generated 3 CRITICAL ransomware alerts
2023-10-15 14:30:00,132 - correlator - INFO - R1 generated 1 alerts
2023-10-15 14:30:00,133 - correlator - INFO - R2 generated 0 alerts
2023-10-15 14:30:00,134 - orchestrator - INFO - Generated 4 alerts
2023-10-15 14:30:00,135 - orchestrator - INFO - Step 3: Executing SOAR actions
Host 192.168.1.50 aislado
Notificación enviada: R3_ransomware_detected: RANSOMWARE DETECTED! Immediate isolation required for 192.168.1.50
Cuenta admin bloqueada
Notificación enviada: RANSOMWARE EMERGENCY: RANSOMWARE DETECTED! Immediate isolation required for 192.168.1.50 - Files affected: 127
```

### Ejecución de Componentes Individuales

#### 1. Collector (Listener Syslog)

```bash
# Iniciar solo el collector en puerto 5140
python collector.py
```

**Comandos de prueba:**

```bash
# Opción 1: Con netcat (si está instalado)
echo "Test syslog message from 192.168.1.100" | nc -u localhost 5140

# Opción 2: Con PowerShell (Windows nativo)
$UdpClient = New-Object System.Net.Sockets.UdpClient
$UdpClient.Connect("localhost", 5140)
$Bytes = [System.Text.Encoding]::UTF8.GetBytes("Test syslog message from 192.168.1.100")
$UdpClient.Send($Bytes, $Bytes.Length)
$UdpClient.Close()

# Opción 3: Probar Collector Syslog (Sin netcat)
```powershell
# Terminal 1: Iniciar collector
python collector.py

# Terminal 2: Enviar mensajes de prueba con nuestro script
python test_syslog.py

# O enviar mensaje personalizado
python test_syslog.py "Custom syslog message from 192.168.1.123"

# Verificar mensajes recibidos
Get-Content test_logs\raw.log -Tail 5
```

**Instalación de netcat para Windows:**
```powershell
# Con chocolatey
choco install netcat

# Con scoop
scoop install netcat

# Descarga directa: https://eternallybored.org/misc/netcat/
```

#### 2. Parser de Eventos

```bash
# Ejecutar solo el parser
python parser.py
```

**Salida esperada:**
```
Parsed 11 events

Event Types:
  authentication_failure: 5
  authentication_success: 1
  ransomware_detected: 3
  info: 2

Top Source IPs:
  192.168.1.50: 9
  192.168.1.100: 1
  192.168.1.200: 1

First 3 parsed events:
  Event 1: {'timestamp': '2023-10-15T14:30:15.123456', 'source_ip': '192.168.1.50', 'event_type': 'authentication_failure', ...}
```

#### 3. Correlator de Eventos

```bash
# Ejecutar solo el correlator
python correlator.py
```

#### 4. Executor de Acciones

```bash
# Probar acciones SOAR
python actions.py
```

**Salida esperada:**
```
Testing SOAR stub functions:
Host 192.168.1.100 aislado
Cuenta admin bloqueada
Notificación enviada: Brute force attack detected from 192.168.1.100

Action Executor initialized and tested
```

## Configuración de Logs de Prueba

### Formato de Logs Soportados

El sistema acepta dos formatos en `test_logs/raw.log`:

#### 1. Formato Texto Plano (Syslog)
```
2023-10-15T14:30:15.123456 [192.168.1.50] Oct 15 14:30:15 server sshd: Failed password for user admin
```

#### 2. Formato JSON
```json
{"timestamp": "2023-10-15T14:31:15.789012", "source_ip": "192.168.1.50", "event_type": "ransomware_detected", "details": "File encryption detected"}
```

### Ejemplos de Logs de Prueba

#### Crear archivo de logs de prueba básico:

```bash
# Crear directorio si no existe
mkdir -p test_logs

# Crear logs de prueba
cat > test_logs/raw.log << 'EOF'
2023-10-15T14:30:15.123456 [192.168.1.50] Oct 15 14:30:15 server sshd: Failed password for user admin
2023-10-15T14:30:25.234567 [192.168.1.50] Oct 15 14:30:25 server sshd: Failed password for user admin
2023-10-15T14:30:35.345678 [192.168.1.50] Oct 15 14:30:35 server sshd: Failed password for user admin
2023-10-15T14:30:45.456789 [192.168.1.50] Oct 15 14:30:45 server sshd: Failed password for user admin
2023-10-15T14:30:55.567890 [192.168.1.50] Oct 15 14:30:55 server sshd: Failed password for user admin
2023-10-15T07:15:00.123456 [192.168.1.100] Oct 15 07:15:00 server login: User john logged in successfully
{"timestamp": "2023-10-15T14:31:15.789012", "source_ip": "192.168.1.50", "event_type": "ransomware_detected", "details": "File encryption activity detected"}
EOF
```

## Escenarios de Prueba

### 1. Simulación de Ataque de Fuerza Bruta

**Logs de entrada:**
```
2023-10-15T14:30:15.123456 [192.168.1.101] Oct 15 14:30:15 server sshd: Failed password for user admin
2023-10-15T14:30:25.234567 [192.168.1.101] Oct 15 14:30:25 server sshd: Failed password for user admin
2023-10-15T14:30:35.345678 [192.168.1.101] Oct 15 14:30:35 server sshd: Failed password for user admin
2023-10-15T14:30:45.456789 [192.168.1.101] Oct 15 14:30:45 server sshd: Failed password for user admin
2023-10-15T14:30:55.567890 [192.168.1.101] Oct 15 14:30:55 server sshd: Failed password for user admin
```

**Respuesta esperada:**
- Detección de regla R1 (5 fallos de login en 5 minutos)
- Aislamiento de host 192.168.1.101
- Bloqueo de IP
- Notificación de incidente

### 2. Simulación de Acceso Fuera de Horario

**Logs de entrada:**
```
2023-10-15T06:30:00.123456 [192.168.1.200] Oct 15 06:30:00 server login: User night_user logged in successfully
```

**Respuesta esperada:**
- Detección de regla R2 (acceso antes de 08:00)
- Recolección de datos forenses
- Notificación de acceso sospechoso

### 3. Simulación de Ransomware (Crítico)

**Logs de entrada:**
```json
{"timestamp": "2023-10-15T14:31:15.789012", "source_ip": "192.168.1.50", "event_type": "ransomware_detected", "details": "File encryption activity detected", "process": "malware.exe", "files_affected": 150}
```

**Respuesta esperada:**
- Detección de regla R3 (ransomware)
- **Aislamiento INMEDIATO** del host
- Bloqueo de cuentas asociadas
- Múltiples notificaciones críticas
- Recolección de evidencia forense

## Testing y Validación

### Ejecutar Tests Completos

```bash
# Ejecutar todos los tests
python -m pytest test_pipeline.py -v

# Ejecutar tests con cobertura
python -m pytest test_pipeline.py --cov=. --cov-report=html

# Ejecutar test específico
python -m pytest test_pipeline.py::TestLogParser::test_parse_json_event -v
```

**Salida esperada de tests:**
```
============================= test session starts =============================
test_pipeline.py::TestLogParser::test_parse_json_event PASSED          [  6%]
test_pipeline.py::TestLogParser::test_parse_plain_text_event PASSED     [ 12%]
test_pipeline.py::TestLogParser::test_detect_event_types PASSED         [ 18%]
test_pipeline.py::TestLogParser::test_parse_raw_logs_with_temp_file PASSED   [ 25%]
test_pipeline.py::TestEventCorrelator::test_rule_r1_login_failures PASSED [ 31%]
test_pipeline.py::TestEventCorrelator::test_rule_r2_off_hours_access PASSED [ 37%]
test_pipeline.py::TestEventCorrelator::test_rule_r3_ransomware_detection PASSED [ 43%]
test_pipeline.py::TestEventCorrelator::test_save_alert_to_csv PASSED         [ 50%]
test_pipeline.py::TestActionExecutor::test_isolate_host PASSED          [ 56%]
test_pipeline.py::TestActionExecutor::test_block_account PASSED         [ 62%]
test_pipeline.py::TestActionExecutor::test_notify_incident PASSED       [ 68%]
test_pipeline.py::TestSIEMOrchestrator::test_execute_soar_actions_ransomware PASSED [ 75%]
test_pipeline.py::TestSIEMOrchestrator::test_execute_soar_actions_brute_force PASSED [ 81%]
test_pipeline.py::TestSIEMOrchestrator::test_execute_soar_actions_off_hours PASSED [ 87%]
test_pipeline.py::TestEndToEndIntegration::test_complete_ransomware_scenario PASSED [ 93%]
test_pipeline.py::TestEndToEndIntegration::test_brute_force_scenario PASSED  [100%]

====================================================== 16 passed in 0.25s ======
```

## 📊 Métricas del Sistema

- **Eventos procesados**: 11 eventos de los logs de prueba
- **Tipos de eventos detectados**: 4 tipos (authentication_failure, info, authentication_success, security_block)
- **Alertas generadas**: 4 alertas críticas (3 de ransomware + 1 de fuerza bruta)
- **Acciones SOAR ejecutadas**: Aislamiento de host, bloqueo de cuenta, notificaciones
- **Tiempo de respuesta**: < 1 segundo para detección y respuesta automática

## 🎯 Componentes Implementados Exitosamente

### ✅ Requerimientos Cumplidos:

1. **✅ Proyecto Python con estructura completa** - `siem_soar/` con todos los módulos
2. **✅ requirements.txt con dependencias** - python-dotenv, pytest y más
3. **✅ Listener UDP syslog** - Puerto 5140, guarda en `test_logs/raw.log`
4. **✅ Parser de eventos** - JSON y texto plano, detección automática de tipos
5. **✅ Reglas de correlación**:
   - **R1**: 5 fallos de login en 5 min → alerta HIGH
   - **R2**: Acceso fuera de horario laboral → alerta MEDIUM
   - **R3**: Detección de ransomware → alerta CRITICAL
6. **✅ Generación de alertas CSV** - `alerts/alerts.log` con formato `rule,timestamp,ip`
7. **✅ Mini-reportes cada 100 eventos** - Estadísticas automáticas
8. **✅ Acciones SOAR stub**:
   - `isolate_host(ip)` ✅
   - `block_account(user)` ✅
   - `notify_incident(details)` ✅
9. **✅ Orquestador end-to-end** - Pipeline completo automatizado
10. **✅ Simulación de ransomware** - Detección y respuesta inmediata
11. **✅ Tests automáticos pytest** - 16 pruebas, 100% éxito
12. **✅ Documentación completa** - README con ejemplos y comandos

## 🔧 Arquitectura del Sistema

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐    ┌──────────────┐
│  Log Sources    │ -> │  Collector   │ -> │   Parser        │ -> │ Correlator   │
│ (Syslog/Files)  │    │ (UDP:5140)   │    │ (JSON/Text)     │    │ (Rules R1-R3)│
└─────────────────┘    └──────────────┘    └─────────────────┘    └──────────────┘
                                                                          │
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐    ┌──────▼──────┐
│   Response      │ <- │ Orchestrator │ <- │     Actions     │ <- │   Alerts    │
│   (Isolation)   │    │ (Pipeline)   │    │ (SOAR/Auto)     │    │ (CSV Log)   │
└─────────────────┘    └──────────────┘    └─────────────────┘    └─────────────┘
```

---

## 🏆 PROYECTO SIEM/SOAR - IMPLEMENTACIÓN EXITOSA COMPLETADA ✅

**Desarrollado por**: [Tu Nombre]  
**Curso**: Redes de Comunicación 3 - Taller 2  
**Universidad**: Universidad Distrital Francisco José de Caldas  
**Fecha**: Junio 2025

---

*Sistema SIEM/SOAR completamente funcional con detección automática de amenazas y respuesta orquestada.*

## 🔧 Solución de Problemas Comunes

### Error: "Port 5140 is already in use"
```powershell
# Problema: Puerto ocupado por instancia anterior
# Solución 1: Terminar procesos Python
taskkill /F /IM python.exe

# Solución 2: Usar puerto alternativo (modificar código)
# En collector.py cambiar puerto a 5141, 5142, etc.

# Solución 3: Usar nuestro script de prueba (recomendado)
python test_syslog.py
```

### Instalación de Netcat (Opcional)
```powershell
# Con Chocolatey
choco install netcat

# Con Scoop  
scoop install netcat

# Descarga manual: https://eternallybored.org/misc/netcat/
```

### Alternativas a Netcat
1. **Script Python** (incluido): `python test_syslog.py` ✅ Recomendado
2. **PowerShell nativo**: Comandos UDP nativos
3. **Telnet**: Para pruebas TCP (no UDP)
