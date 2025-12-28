#!/usr/bin/env python3
"""
Unit tests for the Log Analyzer
"""

import unittest
import tempfile
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, mock_open, MagicMock
import sys
import os

# Add parent directory to path to import log_analyzer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_analyzer import (
    LogAnalyzer, LogEntry, LogAnalysisReport,
    load_config, format_report
)


class TestLogEntry(unittest.TestCase):
    """Test LogEntry dataclass"""
    
    def test_log_entry_creation(self):
        """Test creating a LogEntry instance"""
        entry = LogEntry(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            level="ERROR",
            message="Test error",
            raw_line="2024-01-01 12:00:00 ERROR Test error"
        )
        
        self.assertEqual(entry.level, "ERROR")
        self.assertEqual(entry.message, "Test error")
        self.assertIsNone(entry.response_time)
        

class TestLogAnalyzer(unittest.TestCase):
    """Test LogAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = LogAnalyzer()
        
    def test_initialization(self):
        """Test analyzer initialization"""
        self.assertIsNotNone(self.analyzer.patterns)
        self.assertIsNotNone(self.analyzer.logger)
        self.assertEqual(self.analyzer.stats['total_lines'], 0)
        
    def test_parse_line_with_timestamp(self):
        """Test parsing a line with timestamp"""
        line = "2024-01-01T12:00:00.123 ERROR Failed to connect to database"
        entry = self.analyzer.parse_line(line)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.level, "ERROR")
        self.assertIsNotNone(entry.timestamp)
        self.assertEqual(entry.timestamp.year, 2024)
        
    def test_parse_line_with_response_time(self):
        """Test parsing a line with response time"""
        line = "2024-01-01 12:00:00 INFO Request completed response_time=125.5"
        entry = self.analyzer.parse_line(line)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.response_time, 125.5)
        
    def test_parse_line_with_status_code(self):
        """Test parsing a line with status code"""
        line = "2024-01-01 12:00:00 INFO Request completed status=200"
        entry = self.analyzer.parse_line(line)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status_code, 200)
        
    def test_parse_line_with_endpoint(self):
        """Test parsing a line with endpoint"""
        line = "2024-01-01 12:00:00 INFO GET /api/users completed"
        entry = self.analyzer.parse_line(line)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.endpoint, "GET /api/users")
        
    def test_analyze_entry_error(self):
        """Test analyzing an error entry"""
        entry = LogEntry(
            timestamp=None,
            level="ERROR",
            message="Database connection failed",
            raw_line="ERROR Database connection failed"
        )
        
        self.analyzer.analyze_entry(entry)
        
        self.assertEqual(self.analyzer.stats['total_lines'], 1)
        self.assertEqual(self.analyzer.stats['total_errors'], 1)
        
    def test_analyze_entry_warning(self):
        """Test analyzing a warning entry"""
        entry = LogEntry(
            timestamp=None,
            level="WARNING",
            message="High memory usage",
            raw_line="WARNING High memory usage detected"
        )
        
        self.analyzer.analyze_entry(entry)
        
        self.assertEqual(self.analyzer.stats['total_lines'], 1)
        self.assertEqual(self.analyzer.stats['total_warnings'], 1)
        
    def test_analyze_entry_with_patterns(self):
        """Test pattern detection in entries"""
        entry = LogEntry(
            timestamp=None,
            level="ERROR",
            message="NullPointerException",
            raw_line="ERROR NullPointerException at line 42"
        )
        
        self.analyzer.analyze_entry(entry)
        
        self.assertEqual(self.analyzer.stats['total_errors'], 1)
        self.assertIn('NullPointerException', str(self.analyzer.stats['error_patterns']))
        
    def test_calculate_percentile(self):
        """Test percentile calculation"""
        data = list(range(1, 101))  # 1 to 100
        
        p50 = self.analyzer.calculate_percentile(data, 50)
        p95 = self.analyzer.calculate_percentile(data, 95)
        p99 = self.analyzer.calculate_percentile(data, 99)
        
        self.assertEqual(p50, 50)
        self.assertEqual(p95, 95)
        self.assertEqual(p99, 99)
        
    def test_calculate_percentile_empty(self):
        """Test percentile calculation with empty data"""
        result = self.analyzer.calculate_percentile([], 50)
        self.assertIsNone(result)
        
    def test_generate_report(self):
        """Test report generation"""
        # Add some test data
        self.analyzer.stats['total_lines'] = 100
        self.analyzer.stats['total_errors'] = 10
        self.analyzer.stats['total_warnings'] = 5
        self.analyzer.stats['response_times'] = [100, 200, 300, 400, 500]
        self.analyzer.stats['status_codes'][200] = 80
        self.analyzer.stats['status_codes'][500] = 20
        
        report = self.analyzer.generate_report()
        
        self.assertIsInstance(report, LogAnalysisReport)
        self.assertEqual(report.total_lines, 100)
        self.assertEqual(report.total_errors, 10)
        self.assertEqual(report.total_warnings, 5)
        self.assertEqual(report.avg_response_time, 300)
        self.assertIsNotNone(report.p95_response_time)
        
    def test_analyze_file(self):
        """Test analyzing a file"""
        test_content = """2024-01-01 12:00:00 INFO Application started
2024-01-01 12:00:01 ERROR Database connection failed
2024-01-01 12:00:02 WARNING High memory usage
2024-01-01 12:00:03 INFO GET /api/users response_time=125.5 status=200
2024-01-01 12:00:04 ERROR NullPointerException at line 42
"""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write(test_content)
            temp_file = f.name
            
        try:
            report = self.analyzer.analyze_file(Path(temp_file))
            
            self.assertEqual(report.total_lines, 5)
            self.assertEqual(report.total_errors, 2)
            self.assertEqual(report.total_warnings, 1)
            self.assertEqual(report.total_info, 2)
            self.assertGreater(len(report.error_patterns), 0)
            
        finally:
            os.unlink(temp_file)
            
    def test_analyze_file_not_found(self):
        """Test handling of non-existent file"""
        with self.assertRaises(FileNotFoundError):
            self.analyzer.analyze_file(Path('/non/existent/file.log'))
            
    def test_reset_stats(self):
        """Test resetting statistics"""
        self.analyzer.stats['total_lines'] = 100
        self.analyzer.stats['total_errors'] = 10
        
        self.analyzer.reset_stats()
        
        self.assertEqual(self.analyzer.stats['total_lines'], 0)
        self.assertEqual(self.analyzer.stats['total_errors'], 0)
        

class TestLogAnalysisReport(unittest.TestCase):
    """Test LogAnalysisReport dataclass"""
    
    def test_report_creation(self):
        """Test creating a report"""
        report = LogAnalysisReport(
            total_lines=100,
            total_errors=10,
            total_warnings=5,
            total_info=85,
            error_patterns={'NullPointer': 3},
            warning_patterns={'Deprecated': 2},
            avg_response_time=150.5,
            p95_response_time=500.0,
            p99_response_time=1000.0,
            status_codes={200: 80, 500: 20},
            top_endpoints=[('/api/users', 50)],
            time_range=(datetime(2024, 1, 1), datetime(2024, 1, 2))
        )
        
        self.assertEqual(report.total_lines, 100)
        self.assertEqual(report.total_errors, 10)
        
    def test_report_to_dict(self):
        """Test converting report to dictionary"""
        report = LogAnalysisReport(
            total_lines=100,
            total_errors=10,
            total_warnings=5,
            total_info=85,
            error_patterns={},
            warning_patterns={},
            avg_response_time=None,
            p95_response_time=None,
            p99_response_time=None,
            status_codes={},
            top_endpoints=[],
            time_range=(None, None)
        )
        
        result = report.to_dict()
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['total_lines'], 100)
        

class TestConfigLoading(unittest.TestCase):
    """Test configuration loading"""
    
    def test_load_config_file_not_found(self):
        """Test loading non-existent config file"""
        config = load_config('/non/existent/config.ini')
        self.assertEqual(config, {})
        
    def test_load_config_valid_file(self):
        """Test loading valid config file"""
        config_content = """[DEFAULT]
log_level = DEBUG

[patterns]
error_patterns = ["CustomError", "SpecialException"]
warning_patterns = ["CustomWarning"]
"""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini') as f:
            f.write(config_content)
            temp_file = f.name
            
        try:
            config = load_config(temp_file)
            
            self.assertIn('DEFAULT', config)
            self.assertEqual(config['DEFAULT']['log_level'], 'DEBUG')
            self.assertIn('patterns', config)
            self.assertIsInstance(config['patterns']['error_patterns'], list)
            
        finally:
            os.unlink(temp_file)
            

class TestFormatReport(unittest.TestCase):
    """Test report formatting"""
    
    def test_format_report_text(self):
        """Test text format output"""
        report = LogAnalysisReport(
            total_lines=100,
            total_errors=10,
            total_warnings=5,
            total_info=85,
            error_patterns={'NullPointer': 3},
            warning_patterns={'Deprecated': 2},
            avg_response_time=150.5,
            p95_response_time=500.0,
            p99_response_time=1000.0,
            status_codes={200: 80, 500: 20},
            top_endpoints=[('/api/users', 50)],
            time_range=(datetime(2024, 1, 1), datetime(2024, 1, 2))
        )
        
        output = format_report(report, 'text')
        
        self.assertIn('LOG ANALYSIS REPORT', output)
        self.assertIn('Total lines processed: 100', output)
        self.assertIn('Errors: 10', output)
        
    def test_format_report_json(self):
        """Test JSON format output"""
        report = LogAnalysisReport(
            total_lines=100,
            total_errors=10,
            total_warnings=5,
            total_info=85,
            error_patterns={},
            warning_patterns={},
            avg_response_time=None,
            p95_response_time=None,
            p99_response_time=None,
            status_codes={},
            top_endpoints=[],
            time_range=(None, None)
        )
        
        output = format_report(report, 'json')
        data = json.loads(output)
        
        self.assertEqual(data['total_lines'], 100)
        self.assertEqual(data['total_errors'], 10)
        

class TestIntegration(unittest.TestCase):
    """Integration tests for the complete workflow"""
    
    def test_end_to_end_analysis(self):
        """Test complete analysis workflow"""
        # Create a more complex log file
        test_content = """2024-01-01T10:00:00.000 INFO Application started
2024-01-01T10:00:01.123 INFO GET /api/health response_time=10.5 status=200
2024-01-01T10:00:02.234 INFO POST /api/users response_time=150.2 status=201
2024-01-01T10:00:03.345 WARNING Deprecated API endpoint used
2024-01-01T10:00:04.456 ERROR Database connection failed - Connection refused
2024-01-01T10:00:05.567 ERROR NullPointerException at UserService.java:42
2024-01-01T10:00:06.678 INFO GET /api/products response_time=75.3 status=200
2024-01-01T10:00:07.789 WARNING High memory usage detected: 85%
2024-01-01T10:00:08.890 INFO PUT /api/users/123 response_time=200.1 status=200
2024-01-01T10:00:09.901 ERROR 500 Internal Server Error on /api/orders
2024-01-01T10:00:10.012 INFO DELETE /api/cache response_time=5.2 status=204
2024-01-01T10:00:11.123 WARNING Slow query detected: 5000ms
2024-01-01T10:00:12.234 INFO Application health check passed
2024-01-01T10:00:13.345 ERROR OutOfMemoryError: Java heap space
2024-01-01T10:00:14.456 INFO GET /api/users response_time=95.7 status=200
"""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write(test_content)
            temp_file = f.name
            
        try:
            # Create analyzer with custom config
            config = {
                'log_level': 'INFO'
            }
            analyzer = LogAnalyzer(config)
            
            # Analyze the file
            report = analyzer.analyze_file(Path(temp_file))
            
            # Verify results
            self.assertEqual(report.total_lines, 15)
            self.assertEqual(report.total_errors, 4)
            self.assertEqual(report.total_warnings, 3)
            self.assertGreater(report.total_info, 0)
            
            # Check performance metrics
            self.assertIsNotNone(report.avg_response_time)
            self.assertIsNotNone(report.p95_response_time)
            
            # Check status codes
            self.assertIn(200, report.status_codes)
            
            # Check endpoints
            self.assertGreater(len(report.top_endpoints), 0)
            
            # Check time range
            self.assertIsNotNone(report.time_range[0])
            self.assertIsNotNone(report.time_range[1])
            
            # Test text formatting
            text_output = format_report(report, 'text')
            self.assertIn('LOG ANALYSIS REPORT', text_output)
            
            # Test JSON formatting
            json_output = format_report(report, 'json')
            json_data = json.loads(json_output)
            self.assertEqual(json_data['total_lines'], 15)
            
        finally:
            os.unlink(temp_file)
            
    def test_multiple_files_analysis(self):
        """Test analyzing multiple files"""
        test_content1 = """2024-01-01 12:00:00 ERROR Error in file 1
2024-01-01 12:00:01 INFO Info in file 1
"""
        test_content2 = """2024-01-01 12:00:02 WARNING Warning in file 2
2024-01-01 12:00:03 ERROR Error in file 2
"""
        
        temp_files = []
        try:
            # Create temporary files
            for content in [test_content1, test_content2]:
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
                    f.write(content)
                    temp_files.append(f.name)
                    
            analyzer = LogAnalyzer()
            file_paths = [Path(f) for f in temp_files]
            
            report = analyzer.analyze_files(file_paths)
            
            self.assertEqual(report.total_lines, 4)
            self.assertEqual(report.total_errors, 2)
            self.assertEqual(report.total_warnings, 1)
            self.assertEqual(report.total_info, 1)
            
        finally:
            for temp_file in temp_files:
                os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()
