"""
Log Collector Module
Collects security logs from various sources (files, syslog, network devices, etc.)
"""

import os
import socket
import threading
import logging
from typing import List, Dict, Any
from datetime import datetime

class LogCollector:
    """Collects logs from various sources"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.syslog_socket = None
        self.syslog_thread = None
        self.is_listening = False
        self.raw_log_file = os.path.join("test_logs", "raw.log")
        
        # Ensure test_logs directory exists
        os.makedirs("test_logs", exist_ok=True)
        
    def collect_from_file(self, filepath: str) -> List[str]:
        """Collect logs from a file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                return file.readlines()
        except FileNotFoundError:
            self.logger.error(f"File not found: {filepath}")
            return []
        except Exception as e:
            self.logger.error(f"Error reading file {filepath}: {e}")
            return []
    
    def collect_from_directory(self, directory: str) -> Dict[str, List[str]]:
        """Collect logs from all files in a directory"""
        logs = {}
        try:
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath):
                    logs[filename] = self.collect_from_file(filepath)
            return logs
        except Exception as e:
            self.logger.error(f"Error collecting from directory {directory}: {e}")
            return {}

    def start_syslog_listener(self, port: int = 514, host: str = '0.0.0.0'):
        """Start UDP syslog listener on specified port"""
        try:
            self.syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.syslog_socket.bind((host, port))
            self.is_listening = True
            
            self.logger.info(f"Syslog listener started on {host}:{port}")
            
            # Start listener thread
            self.syslog_thread = threading.Thread(target=self._listen_syslog, daemon=True)
            self.syslog_thread.start()
            self.logger.error(f"Permission denied: Cannot bind to port {port}. Try using port > 1024 or run as administrator.")
            print(f"💡 Suggestion: Try running with a different port, e.g., python collector.py --port 5141")
        except OSError as e:
            if e.errno == 10048:  # Port already in use
                self.logger.error(f"Port {port} is already in use")
                print(f"⚠️  Port {port} is already in use. This might be from a previous instance.")
                print(f"💡 Solutions:")
                print(f"   1. Kill existing Python processes: taskkill /F /IM python.exe")
                print(f"   2. Try a different port: python collector.py --port 5141")
                print(f"   3. Use our test script: python test_syslog.py")
            else:
                self.logger.error(f"Error starting syslog listener: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error starting syslog listener: {e}")
    
    def _listen_syslog(self):
        """Internal method to listen for syslog messages"""
        while self.is_listening:
            try:
                if self.syslog_socket is None:
                    break
                data, addr = self.syslog_socket.recvfrom(1024)  # Buffer size 1024 bytes
                message = data.decode('utf-8', errors='ignore').strip()
                
                if message:
                    self._save_syslog_message(message, addr[0])
                    
            except socket.timeout:
                continue
            except OSError as e:
                if self.is_listening:  # Only log if we're still supposed to be listening
                    self.logger.error(f"Socket error in syslog listener: {e}")
                break
            except Exception as e:
                self.logger.error(f"Error receiving syslog message: {e}")
                
    def _save_syslog_message(self, message: str, source_ip: str):
        """Save syslog message to raw.log with ISO timestamp"""
        try:
            timestamp = datetime.now().isoformat()
            log_entry = f"{timestamp} [{source_ip}] {message}\n"
            
            with open(self.raw_log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
                
            self.logger.debug(f"Saved syslog message from {source_ip}: {message[:50]}...")
            
        except IOError as e:
            self.logger.error(f"Error writing to log file {self.raw_log_file}: {e}")
        except Exception as e:
            self.logger.error(f"Error saving syslog message: {e}")
    
    def stop_syslog_listener(self):
        """Stop the syslog listener"""
        try:
            self.is_listening = False
            
            if self.syslog_socket:
                self.syslog_socket.close()
                self.logger.info("Syslog listener stopped")
                
        except Exception as e:
            self.logger.error(f"Error stopping syslog listener: {e}")
    
    def get_raw_logs(self) -> List[str]:
        """Read and return all raw logs"""
        try:
            if os.path.exists(self.raw_log_file):
                with open(self.raw_log_file, 'r', encoding='utf-8') as f:
                    return f.readlines()
            return []
        except Exception as e:
            self.logger.error(f"Error reading raw log file: {e}")
            return []

if __name__ == "__main__":
    import time
    
    # Setup logging for standalone execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    collector = LogCollector()
    
    # Start syslog listener on a non-privileged port for testing
    try:
        collector.start_syslog_listener(port=5140)  # Using port 5140 instead of 514
        print("Syslog listener started on port 5140. Press Ctrl+C to stop.")
        print("You can test with: echo 'Test syslog message' | nc -u localhost 5140")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping syslog listener...")
        collector.stop_syslog_listener()
        print("Log Collector stopped")
