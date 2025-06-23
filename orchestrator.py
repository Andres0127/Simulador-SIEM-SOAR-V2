"""
SIEM/SOAR Orchestrator
Main orchestration engine that coordinates collection, parsing, correlation and response
"""

import os
import json
import logging
import time
import signal
from typing import List, Dict, Any, Optional
from datetime import datetime

from collector import LogCollector
from parser import LogParser
from correlator import EventCorrelator
from actions import ActionExecutor

class SIEMOrchestrator:
    """Main SIEM/SOAR orchestration engine"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.setup_logging()
        
        # Initialize components
        self.collector = LogCollector()
        self.parser = LogParser()
        self.correlator = EventCorrelator()
        self.action_executor = ActionExecutor()
        
        self.logger = logging.getLogger(__name__)
        self.alerts_dir = "alerts"
        self.test_logs_dir = "test_logs"
        self.is_running = False
        
        # Ensure directories exist
        os.makedirs(self.alerts_dir, exist_ok=True)
        os.makedirs(self.test_logs_dir, exist_ok=True)
        
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('siem.log'),
                logging.StreamHandler()
            ]
        )
        
    def process_log_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Process a single log file"""
        self.logger.info(f"Processing log file: {filepath}")
        
        # Collect logs
        raw_logs = self.collector.collect_from_file(filepath)
        
        # Parse and normalize logs
        parsed_events = []
        for log_line in raw_logs:
            if log_line.strip():  # Skip empty lines
                # Try different parsing methods
                parsed = self.parser.parse_syslog(log_line)
                if not parsed:
                    parsed = self.parser.parse_apache(log_line)
                if not parsed:
                    parsed = self.parser.parse_generic(log_line)
                
                if parsed:
                    normalized = self.parser.normalize_log(parsed)
                    parsed_events.append(normalized)
                    # Add to correlator
                    self.correlator.add_event(normalized)
        
        return parsed_events
        
    def process_directory(self, directory: str) -> Dict[str, List[Dict[str, Any]]]:
        """Process all log files in a directory"""
        self.logger.info(f"Processing directory: {directory}")
        
        results = {}
        try:
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath):
                    results[filename] = self.process_log_file(filepath)
            return results
        except Exception as e:
            self.logger.error(f"Error processing directory {directory}: {e}")
            return {}
            
    def run_correlation(self) -> List[Dict[str, Any]]:
        """Run event correlation and generate alerts"""
        self.logger.info("Running event correlation")
        alerts = self.correlator.correlate_events()
        
        # Save alerts to files
        for alert in alerts:
            self.save_alert(alert)
            
        return alerts
        
    def save_alert(self, alert: Dict[str, Any]):
        """Save alert to file"""
        alert_filename = f"alert_{alert['alert_id']}.json"
        alert_filepath = os.path.join(self.alerts_dir, alert_filename)
        
        try:
            with open(alert_filepath, 'w', encoding='utf-8') as f:
                json.dump(alert, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Alert saved: {alert_filepath}")
        except Exception as e:
            self.logger.error(f"Error saving alert {alert_filename}: {e}")
            
    def execute_response_actions(self, alerts: List[Dict[str, Any]]):
        """Execute automated response actions for alerts"""
        for alert in alerts:
            if alert.get('severity') == 'high':
                self.action_executor.block_ip(alert.get('source_ip', ''))
                self.action_executor.send_notification(alert)
                
    def run_pipeline(self, source_path: Optional[str] = None):
        """Run the complete SIEM pipeline"""
        self.logger.info("Starting SIEM pipeline")
        
        # Use test_logs directory if no source specified
        if source_path is None:
            source_path = self.test_logs_dir
            
        # Process logs
        if os.path.isfile(source_path):
            events = self.process_log_file(source_path)
        elif os.path.isdir(source_path):
            events = self.process_directory(source_path)
        else:
            self.logger.error(f"Invalid source path: {source_path}")
            return
            
        # Run correlation
        alerts = self.run_correlation()
        
        # Execute response actions
        if alerts:
            self.execute_response_actions(alerts)
            self.logger.info(f"Generated {len(alerts)} alerts")
        else:
            self.logger.info("No alerts generated")
            
        # Cleanup old events
        self.correlator.cleanup_old_events()
        
        self.logger.info("SIEM pipeline completed")
    
    def run_end_to_end_flow(self, loop_interval: int = 10, max_iterations: Optional[int] = None):
        """Run the complete SIEM/SOAR pipeline in a continuous loop"""
        self.logger.info("Starting end-to-end SIEM/SOAR flow")
        self.is_running = True
        iteration = 0
        
        try:
            while self.is_running:
                iteration += 1
                self.logger.info(f"Starting iteration {iteration}")
                
                # Step 1: Parse collected logs
                self.logger.info("Step 1: Parsing raw logs")
                parsed_events = self.parser.parse_raw_logs()
                
                if parsed_events:
                    self.logger.info(f"Parsed {len(parsed_events)} events")
                    
                    # Step 2: Run correlation analysis
                    self.logger.info("Step 2: Running correlation analysis")
                    alerts = self.correlator.correlate_events_from_list(parsed_events)
                    
                    if alerts:
                        self.logger.info(f"Generated {len(alerts)} alerts")
                        
                        # Step 3: Execute SOAR actions for each alert
                        self.logger.info("Step 3: Executing SOAR actions")
                        for alert in alerts:
                            self.execute_soar_actions(alert)
                    else:
                        self.logger.info("No alerts generated")
                        
                    # Clear parsed events to avoid reprocessing
                    self.parser.clear_parsed_events()
                else:
                    self.logger.info("No new events to process")
                
                # Check if we should stop (for testing)
                if max_iterations and iteration >= max_iterations:
                    self.logger.info(f"Reached maximum iterations ({max_iterations})")
                    break
                
                # Wait before next iteration
                self.logger.info(f"Waiting {loop_interval} seconds before next iteration")
                time.sleep(loop_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal, stopping orchestrator")
        except Exception as e:
            self.logger.error(f"Error in end-to-end flow: {e}")
        finally:
            self.is_running = False
            self.logger.info("End-to-end flow stopped")
    
    def execute_soar_actions(self, alert: Dict[str, Any]):
        """Execute appropriate SOAR actions based on alert type"""
        try:
            rule_type = alert.get('rule_type', '')
            source_ip = alert.get('source_ip', 'unknown')
            severity = alert.get('severity', 'medium')
            
            self.logger.info(f"Executing SOAR actions for alert: {rule_type}")
            
            # Send notification for all alerts
            notification_details = f"{rule_type}: {alert.get('description', 'Security alert detected')}"
            self.action_executor.notify_incident(notification_details)
            
            # Execute specific actions based on rule type
            if rule_type == 'R3_ransomware_detected':
                # CRITICAL: Ransomware detected - immediate isolation
                self.logger.critical(f"EXECUTING EMERGENCY RANSOMWARE RESPONSE for {source_ip}")
                
                if source_ip != 'unknown':
                    # Immediately isolate the infected host
                    self.action_executor.isolate_host(source_ip)
                    
                    # Block the source IP
                    self.action_executor.block_ip(source_ip)
                    
                    # Collect forensic data
                    self.action_executor.collect_forensic_data(source_ip)
                
                # Block any associated user accounts
                self.action_executor.block_account("admin")  # Block compromised admin account
                
                # Send critical incident notification
                critical_details = f"RANSOMWARE EMERGENCY: {alert.get('description', '')} - Files affected: {alert.get('files_affected', 'unknown')}"
                self.action_executor.notify_incident(critical_details)
                
            elif rule_type == 'R1_login_failures':
                # Brute force attack detected
                if source_ip != 'unknown':
                    # Isolate the attacking host
                    self.action_executor.isolate_host(source_ip)
                    
                    # Block the source IP
                    self.action_executor.block_ip(source_ip)
                
                # If we can extract username from the alert details, block the account
                details = alert.get('description', '')
                if 'user' in details.lower():
                    # Simple extraction - in real scenario would be more sophisticated
                    self.action_executor.block_account("suspected_user")
            
            elif rule_type == 'R2_off_hours_access':
                # Off-hours access detected
                if severity == 'high':
                    # For high severity, isolate the host
                    if source_ip != 'unknown':
                        self.action_executor.isolate_host(source_ip)
                else:
                    # For medium severity, just collect forensic data
                    if source_ip != 'unknown':
                        self.action_executor.collect_forensic_data(source_ip)
            
            # Additional generic actions based on severity
            if severity in ['high', 'critical']:
                # For high/critical severity alerts, take additional protective measures
                self.action_executor.send_notification(alert)
                
        except Exception as e:
            self.logger.error(f"Error executing SOAR actions for alert {alert.get('rule_type', 'unknown')}: {e}")
    
    def start_syslog_collection(self, port: int = 5140):
        """Start syslog collection in background"""
        try:
            self.collector.start_syslog_listener(port=port)
            self.logger.info(f"Started syslog collection on port {port}")
        except Exception as e:
            self.logger.error(f"Error starting syslog collection: {e}")
    
    def stop_syslog_collection(self):
        """Stop syslog collection"""
        try:
            self.collector.stop_syslog_listener()
            self.logger.info("Stopped syslog collection")
        except Exception as e:
            self.logger.error(f"Error stopping syslog collection: {e}")
    
    def stop_orchestrator(self):
        """Stop the orchestrator"""
        self.is_running = False
        self.stop_syslog_collection()
    
    def run_single_iteration(self):
        """Run a single iteration of the pipeline (useful for testing)"""
        self.logger.info("Running single iteration of SIEM pipeline")
        
        # Parse logs
        parsed_events = self.parser.parse_raw_logs()
        self.logger.info(f"Parsed {len(parsed_events)} events")
        
        # Run correlation
        alerts = self.correlator.correlate_events_from_list(parsed_events)
        self.logger.info(f"Generated {len(alerts)} alerts")
        
        # Execute actions
        for alert in alerts:
            self.execute_soar_actions(alert)
        
        return parsed_events, alerts

if __name__ == "__main__":
    import signal
    import sys
    
    def signal_handler(sig, frame):
        print('\nReceived interrupt signal, stopping...')
        orchestrator.stop_orchestrator()
        sys.exit(0)
    
    # Setup signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create and configure orchestrator
    config = {
        'loop_interval': 15,  # Check every 15 seconds
        'syslog_port': 5140   # Use non-privileged port
    }
    
    orchestrator = SIEMOrchestrator(config)
    
    print("Starting SIEM/SOAR Orchestrator")
    print("================================")
    print(f"Syslog listener will start on port {config['syslog_port']}")
    print(f"Pipeline will run every {config['loop_interval']} seconds")
    print("Press Ctrl+C to stop")
    print()
    
    # Start syslog collection
    orchestrator.start_syslog_collection(port=config['syslog_port'])
    
    # Run the end-to-end flow
    orchestrator.run_end_to_end_flow(
        loop_interval=config['loop_interval']
        # max_iterations is optional and defaults to None
    )
