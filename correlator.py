"""
Event Correlator Module
Correlates security events to detect threats and patterns
"""

import os
import csv
import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

class EventCorrelator:
    """Correlates security events to detect threats"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.events = []
        self.rules = []
        self.time_window = timedelta(minutes=5)  # Default correlation window
        self.work_hours_start = 8  # 08:00
        self.work_hours_end = 18   # 18:00
        self.processed_events_count = 0
        self.event_type_counts = defaultdict(int)
        self.alerts_file = os.path.join("alerts", "alerts.log")
        
        # Ensure alerts directory exists
        os.makedirs("alerts", exist_ok=True)
        
        # Initialize CSV alerts file with header if it doesn't exist
        self._initialize_alerts_file()
        
    def _initialize_alerts_file(self):
        """Initialize the alerts CSV file with header if it doesn't exist"""
        try:
            if not os.path.exists(self.alerts_file):
                with open(self.alerts_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['rule', 'timestamp', 'ip'])
                self.logger.info(f"Initialized alerts file: {self.alerts_file}")
        except Exception as e:
            self.logger.error(f"Error initializing alerts file: {e}")
    
    def save_alert_to_csv(self, alert: Dict[str, Any]):
        """Save alert to CSV file in format: rule,timestamp,ip"""
        try:
            with open(self.alerts_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                rule_type = alert.get('rule_type', 'unknown')
                timestamp = alert.get('timestamp', datetime.now().isoformat())
                source_ip = alert.get('source_ip', 'unknown')
                
                writer.writerow([rule_type, timestamp, source_ip])
            
            self.logger.info(f"Alert saved to CSV: {rule_type} - {source_ip}")
            
        except Exception as e:
            self.logger.error(f"Error saving alert to CSV: {e}")
    
    def update_event_counts(self, events: List[Dict[str, Any]]):
        """Update event type counts for reporting"""
        for event in events:
            event_type = event.get('event_type', 'unknown')
            self.event_type_counts[event_type] += 1
            self.processed_events_count += 1
    
    def generate_mini_report(self):
        """Generate and print mini-report of event statistics"""
        print("\n" + "="*50)
        print(f"MINI-REPORT - Processed {self.processed_events_count} events")
        print("="*50)
        print("Event types breakdown:")
        
        # Sort by count (descending)
        sorted_types = sorted(self.event_type_counts.items(), key=lambda x: x[1], reverse=True)
        
        for event_type, count in sorted_types:
            percentage = (count / self.processed_events_count * 100) if self.processed_events_count > 0 else 0
            print(f"  {event_type:<25}: {count:>5} ({percentage:>5.1f}%)")
        
        print("="*50)
        print(f"Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*50 + "\n")
    
    def should_generate_report(self) -> bool:
        """Check if we should generate a mini-report (every 100 events)"""
        return self.processed_events_count > 0 and self.processed_events_count % 100 == 0
        
    def add_event(self, event: Dict[str, Any]):
        """Add an event to the correlation engine"""
        event['correlation_timestamp'] = datetime.now()
        self.events.append(event)
    
    def add_events(self, events: List[Dict[str, Any]]):
        """Add multiple events to the correlation engine"""
        for event in events:
            self.add_event(event)
        
    def add_rule(self, rule: Dict[str, Any]):
        """Add a correlation rule"""
        self.rules.append(rule)
    
    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime object"""
        try:
            # Handle ISO format timestamps
            if 'T' in timestamp_str and '.' in timestamp_str:
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            # Handle other common formats
            elif 'T' in timestamp_str:
                return datetime.fromisoformat(timestamp_str)
            else:
                # Fallback to current time if parsing fails
                return datetime.now()
        except Exception as e:
            self.logger.warning(f"Could not parse timestamp '{timestamp_str}': {e}")
            return datetime.now()
    
    def apply_rule_r1_login_failures(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """R1: Detect 5 login failures from same IP in 5 minutes"""
        alerts = []
        
        # Group events by source IP
        events_by_ip = defaultdict(list)
        
        for event in events:
            # Look for authentication failures
            event_type = event.get('event_type', '').lower()
            details = event.get('details', '').lower()
            
            # Check if this is a login failure event
            is_login_fail = (
                event_type in ['authentication_failure', 'login_fail'] or
                any(keyword in details for keyword in ['failed', 'invalid', 'authentication failure', 'login failed'])
            )
            
            if is_login_fail:
                source_ip = event.get('source_ip', 'unknown')
                if source_ip != 'unknown':
                    events_by_ip[source_ip].append(event)
        
        # Check each IP for multiple failures within time window
        for source_ip, ip_events in events_by_ip.items():
            if len(ip_events) >= 5:
                # Sort events by timestamp
                sorted_events = sorted(ip_events, key=lambda x: self.parse_timestamp(x.get('timestamp', '')))
                
                # Check for 5 failures within 5 minutes
                for i in range(len(sorted_events) - 4):
                    start_time = self.parse_timestamp(sorted_events[i].get('timestamp', ''))
                    end_time = self.parse_timestamp(sorted_events[i + 4].get('timestamp', ''))
                    
                    if end_time - start_time <= self.time_window:
                        alert = {
                            'rule_type': 'R1_login_failures',
                            'timestamp': datetime.now().isoformat(),
                            'source_ip': source_ip,
                            'severity': 'high',
                            'description': f'5 login failures detected from {source_ip} within 5 minutes',
                            'event_count': len(sorted_events),
                            'time_window': str(self.time_window),
                            'first_event_time': sorted_events[0].get('timestamp'),
                            'last_event_time': sorted_events[-1].get('timestamp')
                        }
                        alerts.append(alert)
                        break  # Only generate one alert per IP
        
        return alerts
    
    def apply_rule_r2_off_hours_access(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """R2: Detect successful access outside work hours (before 08:00 or after 18:00)"""
        alerts = []
        
        for event in events:
            event_type = event.get('event_type', '').lower()
            details = event.get('details', '').lower()
            
            # Check if this is a successful authentication/access event
            is_successful_access = (
                event_type in ['authentication_success', 'login_success', 'connection'] or
                any(keyword in details for keyword in ['login successful', 'authenticated', 'logged in', 'session started'])
            )
            
            if is_successful_access:
                try:
                    event_time = self.parse_timestamp(event.get('timestamp', ''))
                    hour = event_time.hour
                    
                    # Check if outside work hours (before 8 AM or after 6 PM)
                    if hour < self.work_hours_start or hour >= self.work_hours_end:
                        source_ip = event.get('source_ip', 'unknown')
                        
                        alert = {
                            'rule_type': 'R2_off_hours_access',
                            'timestamp': datetime.now().isoformat(),
                            'source_ip': source_ip,
                            'severity': 'medium',
                            'description': f'Successful access detected outside work hours from {source_ip} at {event_time.strftime("%H:%M:%S")}',
                            'access_time': event.get('timestamp'),
                            'access_hour': hour,
                            'work_hours': f'{self.work_hours_start:02d}:00-{self.work_hours_end:02d}:00',
                            'event_details': event.get('details', '')
                        }
                        alerts.append(alert)
                        
                except Exception as e:
                    self.logger.error(f"Error processing off-hours rule for event: {e}")
        
        return alerts
    
    def apply_rule_r3_ransomware_detection(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """R3: Detect ransomware activity and trigger immediate response"""
        alerts = []
        
        for event in events:
            event_type = event.get('event_type', '').lower()
            details = event.get('details', '').lower()
            
            # Check if this is a ransomware detection event
            is_ransomware = (
                event_type == 'ransomware_detected' or
                any(keyword in details for keyword in ['ransomware', 'encrypt', 'ransom', 'cryptor'])
            )
            
            if is_ransomware:
                source_ip = event.get('source_ip', 'unknown')
                
                alert = {
                    'rule_type': 'R3_ransomware_detected',
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': source_ip,
                    'severity': 'critical',
                    'description': f'RANSOMWARE DETECTED! Immediate isolation required for {source_ip}',
                    'event_details': event.get('details', ''),
                    'process': event.get('process', event.get('extra_process', 'unknown')),
                    'files_affected': event.get('extra_files_affected', 'unknown'),
                    'requires_immediate_action': True
                }
                
                alerts.append(alert)
                self.logger.critical(f"RANSOMWARE DETECTED from {source_ip}!")
        
        return alerts
    
    def correlate_events_from_list(self, parsed_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply correlation rules to a list of parsed events"""
        alerts = []
        
        # Update event counts for reporting
        self.update_event_counts(parsed_events)
        
        try:
            # Apply R3: Ransomware detection (CRITICAL - check first)
            r3_alerts = self.apply_rule_r3_ransomware_detection(parsed_events)
            alerts.extend(r3_alerts)
            if r3_alerts:
                self.logger.critical(f"R3 generated {len(r3_alerts)} CRITICAL ransomware alerts")
            
            # Apply R1: Login failure detection
            r1_alerts = self.apply_rule_r1_login_failures(parsed_events)
            alerts.extend(r1_alerts)
            self.logger.info(f"R1 generated {len(r1_alerts)} alerts")
            
            # Apply R2: Off-hours access detection
            r2_alerts = self.apply_rule_r2_off_hours_access(parsed_events)
            alerts.extend(r2_alerts)
            self.logger.info(f"R2 generated {len(r2_alerts)} alerts")
            
            # Save alerts to CSV
            for alert in alerts:
                self.save_alert_to_csv(alert)
            
            # Generate mini-report if we've processed 100 events
            if self.should_generate_report():
                self.generate_mini_report()
            
        except Exception as e:
            self.logger.error(f"Error during event correlation: {e}")
        
        return alerts
    
    def correlate_events(self) -> List[Dict[str, Any]]:
        """Run all correlation rules and return alerts"""
        return self.correlate_events_from_list(self.events)
        
    def cleanup_old_events(self, retention_hours: int = 24):
        """Remove old events to prevent memory issues"""
        cutoff_time = datetime.now() - timedelta(hours=retention_hours)
        self.events = [
            event for event in self.events
            if event.get('correlation_timestamp', datetime.now()) > cutoff_time
        ]

if __name__ == "__main__":
    # Setup logging for standalone execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    correlator = EventCorrelator()
    
    # Test with sample events to demonstrate reporting
    test_events = []
    
    # Generate 150 test events to trigger multiple reports
    for i in range(150):
        event_types = ['authentication_failure', 'authentication_success', 'connection', 'error', 'warning']
        source_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102', '10.0.0.1']
        
        event = {
            'timestamp': f'2023-10-15T{(7 + i//10) % 24:02d}:{(i*2) % 60:02d}:00.000000',
            'source_ip': source_ips[i % len(source_ips)],
            'event_type': event_types[i % len(event_types)],
            'details': f'Test event {i+1}'
        }
        test_events.append(event)
    
    # Process events in batches to see multiple reports
    batch_size = 50
    for i in range(0, len(test_events), batch_size):
        batch = test_events[i:i+batch_size]
        alerts = correlator.correlate_events_from_list(batch)
        print(f"Batch {i//batch_size + 1}: Generated {len(alerts)} alerts")
    
    print(f"\nTotal processed events: {correlator.processed_events_count}")
    print(f"Alerts saved to: {correlator.alerts_file}")
    
    # Test with ransomware simulation events
    test_events = [
        {
            'timestamp': '2023-10-15T14:30:15.123456',
            'source_ip': '192.168.1.50',
            'event_type': 'authentication_failure',
            'details': 'Failed password for user admin'
        },
        {
            'timestamp': '2023-10-15T14:31:15.789012',
            'source_ip': '192.168.1.50',
            'event_type': 'ransomware_detected',
            'details': 'File encryption activity detected on C:\\Users\\Documents\\*.docx',
            'extra_process': 'suspicious_encrypt.exe',
            'extra_files_affected': 127
        }
    ]
    
    alerts = correlator.correlate_events_from_list(test_events)
    print(f"Generated {len(alerts)} alerts")
    
    for alert in alerts:
        print(f"Alert: {alert['rule_type']} - {alert['description']} - Severity: {alert['severity']}")
