"""
Log Parser Module
Parses and normalizes security logs from different formats
"""

import re
import json
import logging
import os
from typing import Dict, Any, List
from datetime import datetime

class LogParser:
    """Parses and normalizes security logs"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.parsed_events = []  # Store parsed events in memory
        self.raw_log_file = os.path.join("test_logs", "raw.log")
        self.patterns = {
            'syslog': r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+):\s+(?P<message>.*)',
            'apache': r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\d+)',
            'windows': r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?P<source>\S+)\s+(?P<event_id>\d+)\s+(?P<message>.*)'
        }
    
    def parse_syslog(self, log_line: str) -> Dict[str, Any]:
        """Parse syslog format"""
        match = re.match(self.patterns['syslog'], log_line.strip())
        if match:
            return {
                'timestamp': match.group('timestamp'),
                'hostname': match.group('hostname'),
                'process': match.group('process'),
                'message': match.group('message'),
                'log_type': 'syslog'
            }
        return {}
    
    def parse_apache(self, log_line: str) -> Dict[str, Any]:
        """Parse Apache access log format"""
        match = re.match(self.patterns['apache'], log_line.strip())
        if match:
            return {
                'timestamp': match.group('timestamp'),
                'source_ip': match.group('ip'),
                'method': match.group('method'),
                'url': match.group('url'),
                'status_code': int(match.group('status')),
                'log_type': 'apache'
            }
        return {}
    
    def parse_generic(self, log_line: str, log_type: str = 'generic') -> Dict[str, Any]:
        """Parse generic log format"""
        return {
            'timestamp': datetime.now().isoformat(),
            'raw_message': log_line.strip(),
            'log_type': log_type
        }
    
    def normalize_log(self, parsed_log: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize parsed log to common format"""
        normalized = {
            'timestamp': parsed_log.get('timestamp', datetime.now().isoformat()),
            'source': parsed_log.get('hostname', parsed_log.get('source_ip', 'unknown')),
            'message': parsed_log.get('message', parsed_log.get('raw_message', '')),
            'log_type': parsed_log.get('log_type', 'unknown'),
            'severity': 'info'  # Default severity
        }
        return normalized
    
    def is_json(self, text: str) -> bool:
        """Check if text is valid JSON"""
        try:
            json.loads(text)
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    def parse_json_event(self, json_text: str) -> Dict[str, Any]:
        """Parse JSON formatted log entry"""
        try:
            data = json.loads(json_text)
            
            # Extract standard fields or use defaults
            parsed_event = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'source_ip': data.get('source_ip', data.get('src_ip', data.get('ip', 'unknown'))),
                'event_type': data.get('event_type', data.get('type', data.get('category', 'unknown'))),
                'details': data.get('details', data.get('message', data.get('description', str(data))))
            }
            
            # Add any additional fields from the JSON
            for key, value in data.items():
                if key not in ['timestamp', 'source_ip', 'event_type', 'details']:
                    parsed_event[f'extra_{key}'] = value
                    
            return parsed_event
            
        except Exception as e:
            self.logger.error(f"Error parsing JSON event: {e}")
            return {}
    
    def parse_plain_text_event(self, text_line: str) -> Dict[str, Any]:
        """Parse plain text log entry from raw.log format"""
        try:
            # Expected format: "2023-10-15T10:00:00.000000 [192.168.1.100] actual syslog message"
            pattern = r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)\s+\[(?P<source_ip>[^\]]+)\]\s+(?P<message>.*)'
            match = re.match(pattern, text_line.strip())
            
            if match:
                message = match.group('message')
                event_type = self._detect_event_type(message)
                
                parsed_event = {
                    'timestamp': match.group('timestamp'),
                    'source_ip': match.group('source_ip'),
                    'event_type': event_type,
                    'details': message
                }
                
                # Try to parse common syslog formats for additional info
                syslog_parsed = self.parse_syslog(message)
                if syslog_parsed:
                    parsed_event.update({
                        'hostname': syslog_parsed.get('hostname', 'unknown'),
                        'process': syslog_parsed.get('process', 'unknown'),
                        'syslog_message': syslog_parsed.get('message', message)
                    })
                
                return parsed_event
            else:
                # Fallback for lines that don't match expected format
                return {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': 'unknown',
                    'event_type': 'unparsed',
                    'details': text_line.strip()
                }                
        except Exception as e:
            self.logger.error(f"Error parsing plain text event: {e}")
            return {}
    
    def _detect_event_type(self, message: str) -> str:
        """Detect event type based on message content"""
        message_lower = message.lower()
        
        if any(keyword in message_lower for keyword in ['failed', 'invalid', 'authentication failure']):
            return 'authentication_failure'
        elif any(keyword in message_lower for keyword in ['firewall', 'blocked', 'denied']):
            return 'security_block'
        elif any(keyword in message_lower for keyword in ['logged in successfully', 'login successful', 'authenticated successfully']):
            return 'authentication_success'
        elif any(keyword in message_lower for keyword in ['login', 'logon', 'authenticated']):
            return 'authentication_success'
        elif any(keyword in message_lower for keyword in ['connection', 'connect', 'session']):
            return 'connection'
        elif any(keyword in message_lower for keyword in ['error', 'critical', 'alert']):
            return 'error'
        elif any(keyword in message_lower for keyword in ['warning', 'warn']):
            return 'warning'
        else:
            return 'info'
    
    def parse_raw_logs(self) -> List[Dict[str, Any]]:
        """Read and parse all entries from raw.log file"""
        self.parsed_events.clear()  # Clear previous events
        
        try:
            if not os.path.exists(self.raw_log_file):
                self.logger.warning(f"Raw log file not found: {self.raw_log_file}")
                return []
            
            with open(self.raw_log_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:  # Skip empty lines
                        continue
                    
                    try:
                        if self.is_json(line):
                            parsed_event = self.parse_json_event(line)
                        else:
                            parsed_event = self.parse_plain_text_event(line)
                        
                        if parsed_event:
                            parsed_event['line_number'] = line_num
                            parsed_event['raw_line'] = line
                            self.parsed_events.append(parsed_event)
                            
                    except Exception as e:
                        self.logger.error(f"Error parsing line {line_num}: {e}")
                        # Add unparseable line as raw event
                        self.parsed_events.append({
                            'timestamp': datetime.now().isoformat(),
                            'source_ip': 'unknown',
                            'event_type': 'parse_error',
                            'details': f"Parse error: {str(e)}",
                            'line_number': line_num,
                            'raw_line': line
                        })
            
            self.logger.info(f"Parsed {len(self.parsed_events)} events from {self.raw_log_file}")
            return self.parsed_events.copy()
            
        except IOError as e:
            self.logger.error(f"Error reading raw log file {self.raw_log_file}: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error parsing raw logs: {e}")
            return []
    
    def get_parsed_events(self) -> List[Dict[str, Any]]:
        """Get the current list of parsed events in memory"""
        return self.parsed_events.copy()
    
    def get_events_by_type(self, event_type: str) -> List[Dict[str, Any]]:
        """Get events filtered by event type"""
        return [event for event in self.parsed_events if event.get('event_type') == event_type]
    
    def get_events_by_source_ip(self, source_ip: str) -> List[Dict[str, Any]]:
        """Get events filtered by source IP"""
        return [event for event in self.parsed_events if event.get('source_ip') == source_ip]
    
    def clear_parsed_events(self):
        """Clear all parsed events from memory"""
        self.parsed_events.clear()
        self.logger.info("Cleared all parsed events from memory")

if __name__ == "__main__":
    import time
    
    # Setup logging for standalone execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = LogParser()
    
    # Parse raw logs
    events = parser.parse_raw_logs()
    print(f"Parsed {len(events)} events")
    
    # Display some statistics
    event_types = {}
    source_ips = {}
    
    for event in events:
        event_type = event.get('event_type', 'unknown')
        source_ip = event.get('source_ip', 'unknown')
        
        event_types[event_type] = event_types.get(event_type, 0) + 1
        source_ips[source_ip] = source_ips.get(source_ip, 0) + 1
    
    print("\nEvent Types:")
    for event_type, count in event_types.items():
        print(f"  {event_type}: {count}")
    
    print("\nTop Source IPs:")
    for source_ip, count in sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {source_ip}: {count}")
    
    # Show first few events
    print("\nFirst 3 parsed events:")
    for i, event in enumerate(events[:3]):
        print(f"  Event {i+1}: {event}")
