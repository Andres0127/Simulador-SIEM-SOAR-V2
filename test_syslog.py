#!/usr/bin/env python3
"""
Test script para enviar mensajes syslog al collector
No requiere netcat - funciona en cualquier sistema con Python
"""

import socket
import time
import sys

def send_syslog_message(message, host='localhost', port=5140):
    """Envía un mensaje syslog por UDP"""
    try:
        # Crear socket UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)  # Timeout de 5 segundos
        
        # Enviar mensaje
        sock.sendto(message.encode('utf-8'), (host, port))
        sock.close()
        
        print(f"✅ Mensaje enviado a {host}:{port}")
        print(f"📨 Contenido: {message}")
        return True
        
    except socket.timeout:
        print(f"⏰ Timeout: No se pudo conectar a {host}:{port}")
        print(f"💡 Solución: Asegúrate de que el collector esté ejecutándose:")
        print(f"   python collector.py")
        return False
    except ConnectionRefusedError:
        print(f"❌ Conexión rechazada: No hay listener en {host}:{port}")
        print(f"💡 Solución: Inicia el collector en otra terminal:")
        print(f"   python collector.py")
        return False
    except Exception as e:
        print(f"❌ Error enviando mensaje: {e}")
        print(f"💡 Verifica que el collector esté ejecutándose en puerto {port}")
        return False

def check_collector_status(host='localhost', port=5140):
    """Verifica si el collector está ejecutándose"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        # Enviar un mensaje de prueba pequeño
        test_msg = "HEALTH_CHECK"
        sock.sendto(test_msg.encode('utf-8'), (host, port))
        sock.close()
        return True
    except:
        return False

def test_scenarios():
    """Ejecuta varios escenarios de prueba"""
    
    print("🧪 INICIANDO PRUEBAS DEL LISTENER SYSLOG")
    print("="*50)
    
    # Verificar si el collector está ejecutándose
    print("🔍 Verificando estado del collector...")
    if not check_collector_status():
        print("⚠️  ADVERTENCIA: El collector no parece estar ejecutándose")
        print("💡 Para iniciar el collector, ejecuta en otra terminal:")
        print("   python collector.py")
        print("\n⚡ Continuando con las pruebas (los mensajes se perderán si no hay collector)...")
        time.sleep(2)
    else:
        print("✅ Collector detectado - ¡Listo para enviar mensajes!")
    
    print()
    
    # Escenario 1: Login fallido
    print("1️⃣ Simulando fallo de login...")
    send_syslog_message("Oct 22 18:45:00 server sshd: Failed password for user admin from 192.168.1.101")
    time.sleep(1)
    
    # Escenario 2: Login exitoso fuera de horario
    print("\n2️⃣ Simulando login fuera de horario...")
    send_syslog_message("Oct 22 06:30:00 server login: User nightuser logged in successfully from 192.168.1.200")
    time.sleep(1)
    
    # Escenario 3: Actividad de firewall
    print("\n3️⃣ Simulando bloqueo de firewall...")
    send_syslog_message("Oct 22 18:45:30 firewall: Connection blocked from 203.0.113.5 to port 22")
    time.sleep(1)
    
    # Escenario 4: Mensaje de prueba genérico
    print("\n4️⃣ Enviando mensaje de prueba...")
    send_syslog_message("Test syslog message from test_syslog.py script")
    time.sleep(1)
    
    print("\n✅ PRUEBAS COMPLETADAS")
    print("💡 Revisa el archivo test_logs/raw.log para ver los mensajes recibidos")
    print("📋 Comando: Get-Content test_logs\\raw.log -Tail 5")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Enviar mensaje personalizado
        custom_message = " ".join(sys.argv[1:])
        send_syslog_message(custom_message)
    else:
        # Ejecutar escenarios de prueba
        test_scenarios()
