"""
Automated tests for SIEM/SOAR pipeline
Tests parser, correlator, and orchestrator functionality
"""

import pytest
import os
import tempfile
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from parser import LogParser
from correlator import EventCorrelator
from orchestrator import SIEMOrchestrator
from actions import ActionExecutor

class TestLogParser:
    """Test cases for LogParser functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.parser = LogParser()
        
    def test_parse_json_event(self):
        """Test JSON event parsing"""
        json_line = '{"timestamp": "2023-10-15T14:31:15.789012", "source_ip": "192.168.1.50", "event_type": "ransomware_detected", "details": "File encryption detected"}'
        
        result = self.parser.parse_json_event(json_line)
        
        assert result['timestamp'] == "2023-10-15T14:31:15.789012"
        assert result['source_ip'] == "192.168.1.50"
        assert result['event_type'] == "ransomware_detected"
        assert result['details'] == "File encryption detected"
        
    def test_parse_plain_text_event(self):
        """Test plain text event parsing"""
        text_line = "2023-10-15T14:30:15.123456 [192.168.1.50] Oct 15 14:30:15 server sshd: Failed password for user admin"
        
        result = self.parser.parse_plain_text_event(text_line)
        
        assert result['timestamp'] == "2023-10-15T14:30:15.123456"
        assert result['source_ip'] == "192.168.1.50"
        assert result['event_type'] == "authentication_failure"
        assert "Failed password" in result['details']
        
    def test_detect_event_types(self):
        """Test event type detection"""
        test_cases = [
            ("Failed password for user admin", "authentication_failure"),
            ("User logged in successfully", "authentication_success"),
            ("Connection established", "connection"),
            ("Critical system error", "error"),
            ("Warning: disk space low", "warning"),
            ("Firewall blocked connection", "security_block"),
            ("Normal operation", "info")
        ]
        
        for message, expected_type in test_cases:
            result = self.parser._detect_event_type(message)
            assert result == expected_type, f"Expected {expected_type} for '{message}', got {result}"
            
    def test_parse_raw_logs_with_temp_file(self):
        """Test parsing raw logs from temporary file"""
        test_content = """2023-10-15T14:30:15.123456 [192.168.1.50] Oct 15 14:30:15 server sshd: Failed password for user admin
{"timestamp": "2023-10-15T14:31:15.789012", "source_ip": "192.168.1.50", "event_type": "ransomware_detected", "details": "File encryption detected"}
2023-10-15T14:32:00.012345 [192.168.1.100] Oct 15 14:32:00 server login: User john logged in successfully"""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write(test_content)
            temp_file = f.name
            
        # Temporarily change the raw log file path
        original_path = self.parser.raw_log_file
        self.parser.raw_log_file = temp_file
        
        try:
            events = self.parser.parse_raw_logs()
            
            assert len(events) == 3
            assert events[0]['event_type'] == 'authentication_failure'
            assert events[1]['event_type'] == 'ransomware_detected'
            assert events[2]['event_type'] == 'authentication_success'
            
        finally:
            self.parser.raw_log_file = original_path
            os.unlink(temp_file)

class TestEventCorrelator:
    """Test cases for EventCorrelator functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.correlator = EventCorrelator()
        
    def test_rule_r1_login_failures(self):
        """Test R1: Multiple login failures detection"""
        # Create 5 login failure events within 5 minutes
        base_time = datetime.now()
        events = []
        
        for i in range(5):
            event_time = base_time + timedelta(minutes=i)
            events.append({
                'timestamp': event_time.isoformat(),
                'source_ip': '192.168.1.50',
                'event_type': 'authentication_failure',
                'details': 'Failed password for user admin'
            })
            
        alerts = self.correlator.apply_rule_r1_login_failures(events)
        
        assert len(alerts) == 1
        assert alerts[0]['rule_type'] == 'R1_login_failures'
        assert alerts[0]['source_ip'] == '192.168.1.50'
        assert alerts[0]['severity'] == 'high'
        
    def test_rule_r2_off_hours_access(self):
        """Test R2: Off-hours access detection"""
        # Create successful login at 7 AM (before work hours)
        early_morning = datetime.now().replace(hour=7, minute=30)
        
        events = [{
            'timestamp': early_morning.isoformat(),
            'source_ip': '192.168.1.100',
            'event_type': 'authentication_success',
            'details': 'User logged in successfully'
        }]
        
        alerts = self.correlator.apply_rule_r2_off_hours_access(events)
        
        assert len(alerts) == 1
        assert alerts[0]['rule_type'] == 'R2_off_hours_access'
        assert alerts[0]['source_ip'] == '192.168.1.100'
        assert alerts[0]['severity'] == 'medium'
        
    def test_rule_r3_ransomware_detection(self):
        """Test R3: Ransomware detection"""
        events = [{
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.50',
            'event_type': 'ransomware_detected',
            'details': 'File encryption activity detected',
            'extra_process': 'suspicious_encrypt.exe',
            'extra_files_affected': 127
        }]
        
        alerts = self.correlator.apply_rule_r3_ransomware_detection(events)
        
        assert len(alerts) == 1
        assert alerts[0]['rule_type'] == 'R3_ransomware_detected'
        assert alerts[0]['source_ip'] == '192.168.1.50'
        assert alerts[0]['severity'] == 'critical'
        assert alerts[0]['requires_immediate_action'] == True
        
    @patch('csv.writer')
    def test_save_alert_to_csv(self, mock_csv_writer):
        """Test saving alerts to CSV"""
        mock_writer = Mock()
        mock_csv_writer.return_value = mock_writer
        
        alert = {
            'rule_type': 'R1_login_failures',
            'timestamp': '2023-10-15T14:30:00.000000',
            'source_ip': '192.168.1.50'
        }
        
        with patch('builtins.open', create=True) as mock_open:
            self.correlator.save_alert_to_csv(alert)
            
        mock_writer.writerow.assert_called_once_with(['R1_login_failures', '2023-10-15T14:30:00.000000', '192.168.1.50'])

class TestActionExecutor:
    """Test cases for ActionExecutor SOAR functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.executor = ActionExecutor()
        
    def test_isolate_host(self):
        """Test host isolation action"""
        with patch('builtins.print') as mock_print:
            result = self.executor.isolate_host('192.168.1.50')
            
        assert result == True
        mock_print.assert_called_with('Host 192.168.1.50 aislado')
        assert len(self.executor.action_log) == 1
        assert self.executor.action_log[0]['action_type'] == 'isolate_host'
        
    def test_block_account(self):
        """Test account blocking action"""
        with patch('builtins.print') as mock_print:
            result = self.executor.block_account('admin')
            
        assert result == True
        mock_print.assert_called_with('Cuenta admin bloqueada')
        assert len(self.executor.action_log) == 1
        assert self.executor.action_log[0]['action_type'] == 'block_account'
        
    def test_notify_incident(self):
        """Test incident notification action"""
        with patch('builtins.print') as mock_print:
            result = self.executor.notify_incident('Ransomware detected')
            
        assert result == True
        mock_print.assert_called_with('Notificación enviada: Ransomware detected')
        assert len(self.executor.action_log) == 1
        assert self.executor.action_log[0]['action_type'] == 'notify_incident'

class TestSIEMOrchestrator:
    """Test cases for SIEMOrchestrator integration"""
    
    def setup_method(self):
        """Setup test environment"""
        self.orchestrator = SIEMOrchestrator()
        
    def test_execute_soar_actions_ransomware(self):
        """Test SOAR actions for ransomware alert"""
        alert = {
            'rule_type': 'R3_ransomware_detected',
            'source_ip': '192.168.1.50',
            'severity': 'critical',
            'description': 'Ransomware detected on host',
            'files_affected': 127
        }
        
        with patch.object(self.orchestrator.action_executor, 'isolate_host') as mock_isolate, \
             patch.object(self.orchestrator.action_executor, 'block_ip') as mock_block_ip, \
             patch.object(self.orchestrator.action_executor, 'block_account') as mock_block_account, \
             patch.object(self.orchestrator.action_executor, 'notify_incident') as mock_notify:
            
            self.orchestrator.execute_soar_actions(alert)
            
            mock_isolate.assert_called_with('192.168.1.50')
            mock_block_ip.assert_called_with('192.168.1.50')
            mock_block_account.assert_called_with('admin')
            assert mock_notify.call_count == 2  # Two notifications for ransomware
            
    def test_execute_soar_actions_brute_force(self):
        """Test SOAR actions for brute force alert"""
        alert = {
            'rule_type': 'R1_login_failures',
            'source_ip': '192.168.1.101',
            'severity': 'high',
            'description': 'Brute force attack detected'
        }
        
        with patch.object(self.orchestrator.action_executor, 'isolate_host') as mock_isolate, \
             patch.object(self.orchestrator.action_executor, 'block_ip') as mock_block_ip, \
             patch.object(self.orchestrator.action_executor, 'notify_incident') as mock_notify:
            
            self.orchestrator.execute_soar_actions(alert)
            
            mock_isolate.assert_called_with('192.168.1.101')
            mock_block_ip.assert_called_with('192.168.1.101')
            mock_notify.assert_called()
            
    def test_execute_soar_actions_off_hours(self):
        """Test SOAR actions for off-hours access alert"""
        alert = {
            'rule_type': 'R2_off_hours_access',
            'source_ip': '192.168.1.200',
            'severity': 'medium',
            'description': 'Off-hours access detected'
        }
        
        with patch.object(self.orchestrator.action_executor, 'collect_forensic_data') as mock_forensics, \
             patch.object(self.orchestrator.action_executor, 'notify_incident') as mock_notify:
            
            self.orchestrator.execute_soar_actions(alert)
            
            mock_forensics.assert_called_with('192.168.1.200')
            mock_notify.assert_called()

class TestEndToEndIntegration:
    """End-to-end integration tests"""
    
    def setup_method(self):
        """Setup test environment"""
        self.orchestrator = SIEMOrchestrator()
        
    def test_complete_ransomware_scenario(self):
        """Test complete ransomware detection and response pipeline"""
        # Create test events simulating ransomware scenario
        test_events = [
            # Multiple login failures
            {
                'timestamp': '2023-10-15T14:30:15.123456',
                'source_ip': '192.168.1.50',
                'event_type': 'authentication_failure',
                'details': 'Failed password for user admin'
            },
            {
                'timestamp': '2023-10-15T14:30:25.234567',
                'source_ip': '192.168.1.50',
                'event_type': 'authentication_failure',
                'details': 'Failed password for user admin'
            },
            # Successful login
            {
                'timestamp': '2023-10-15T14:31:05.678901',
                'source_ip': '192.168.1.50',
                'event_type': 'authentication_success',
                'details': 'User admin logged in successfully'
            },
            # Ransomware detection
            {
                'timestamp': '2023-10-15T14:31:15.789012',
                'source_ip': '192.168.1.50',
                'event_type': 'ransomware_detected',
                'details': 'File encryption activity detected',
                'extra_process': 'suspicious_encrypt.exe',
                'extra_files_affected': 127
            }
        ]
        
        # Mock the action executor methods
        with patch.object(self.orchestrator.action_executor, 'isolate_host') as mock_isolate, \
             patch.object(self.orchestrator.action_executor, 'block_ip') as mock_block_ip, \
             patch.object(self.orchestrator.action_executor, 'notify_incident') as mock_notify:
            
            # Run correlation on test events
            alerts = self.orchestrator.correlator.correlate_events_from_list(test_events)
            
            # Execute SOAR actions for each alert
            for alert in alerts:
                self.orchestrator.execute_soar_actions(alert)
            
            # Verify ransomware was detected and actions were taken
            ransomware_alerts = [a for a in alerts if a['rule_type'] == 'R3_ransomware_detected']
            assert len(ransomware_alerts) == 1
            
            # Verify isolation was called for ransomware
            mock_isolate.assert_called()
            mock_notify.assert_called()
            
    def test_brute_force_scenario(self):
        """Test complete brute force detection and response pipeline"""
        # Create 5 login failure events within time window
        base_time = datetime.now()
        test_events = []
        
        for i in range(5):
            event_time = base_time + timedelta(seconds=i*30)  # 30 seconds apart
            test_events.append({
                'timestamp': event_time.isoformat(),
                'source_ip': '192.168.1.101',
                'event_type': 'authentication_failure',
                'details': 'Failed password for user admin'
            })
        
        with patch.object(self.orchestrator.action_executor, 'isolate_host') as mock_isolate, \
             patch.object(self.orchestrator.action_executor, 'block_ip') as mock_block_ip:
            
            alerts = self.orchestrator.correlator.correlate_events_from_list(test_events)
            
            for alert in alerts:
                self.orchestrator.execute_soar_actions(alert)
            
            # Verify brute force was detected
            brute_force_alerts = [a for a in alerts if a['rule_type'] == 'R1_login_failures']
            assert len(brute_force_alerts) == 1
            
            # Verify actions were taken
            mock_isolate.assert_called_with('192.168.1.101')
            mock_block_ip.assert_called_with('192.168.1.101')

if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
