#!/usr/bin/env python3
"""
Log Analyzer - A DevOps automation tool for analyzing application logs
Description: Analyzes application logs to summarize errors, warnings, and performance metrics
"""

import argparse
import json
import logging
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import configparser
from dataclasses import dataclass, asdict


@dataclass
class LogEntry:
    """Represents a parsed log entry"""
    timestamp: Optional[datetime]
    level: str
    message: str
    raw_line: str
    response_time: Optional[float] = None
    status_code: Optional[int] = None
    endpoint: Optional[str] = None


@dataclass
class LogAnalysisReport:
    """Contains the analysis results"""
    total_lines: int
    total_errors: int
    total_warnings: int
    total_info: int
    error_patterns: Dict[str, int]
    warning_patterns: Dict[str, int]
    avg_response_time: Optional[float]
    p95_response_time: Optional[float]
    p99_response_time: Optional[float]
    status_codes: Dict[int, int]
    top_endpoints: List[Tuple[str, int]]
    time_range: Tuple[Optional[datetime], Optional[datetime]]
    
    def to_dict(self) -> Dict:
        """Convert report to dictionary for JSON serialization"""
        result = asdict(self)
        # Convert datetime objects to strings
        if self.time_range[0]:
            result['time_range'] = [
                self.time_range[0].isoformat() if self.time_range[0] else None,
                self.time_range[1].isoformat() if self.time_range[1] else None
            ]
        return result


class LogAnalyzer:
    """Main class for analyzing application logs"""
    
    # Common log patterns (configurable)
    DEFAULT_PATTERNS = {
        'timestamp': r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)',
        'level': r'(ERROR|WARN|WARNING|INFO|DEBUG|CRITICAL|FATAL)',
        'response_time': r'response_time[=:](\d+\.?\d*)',
        'status_code': r'status[_code]*[=:](\d{3})',
        'endpoint': r'((?:GET|POST|PUT|DELETE|PATCH)\s+/[\w/\-\.]+)',
        'error_patterns': [
            r'NullPointerException',
            r'OutOfMemoryError',
            r'Connection refused',
            r'Timeout',
            r'Database connection failed',
            r'Authentication failed',
            r'Permission denied',
            r'File not found',
            r'500 Internal Server Error',
            r'503 Service Unavailable'
        ],
        'warning_patterns': [
            r'Deprecated',
            r'High memory usage',
            r'Slow query',
            r'Rate limit exceeded',
            r'Certificate expiring',
            r'Disk space low',
            r'Cache miss',
            r'Retry attempt'
        ]
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the log analyzer with optional configuration"""
        self.config = config or {}
        self.setup_logging()
        self.setup_patterns()
        self.reset_stats()
        
    def setup_logging(self):
        """Configure logging for the analyzer itself"""
        log_level = self.config.get('log_level', 'INFO')
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(
                    self.config.get('analyzer_log_file', 'log_analyzer.log')
                )
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_patterns(self):
        """Setup regex patterns from configuration or defaults"""
        patterns = self.config.get('patterns', {})
        
        # Merge with defaults
        for key, value in self.DEFAULT_PATTERNS.items():
            if key not in patterns:
                patterns[key] = value
                
        # Compile regex patterns
        self.patterns = {}
        for key, pattern in patterns.items():
            if isinstance(pattern, list):
                self.patterns[key] = [re.compile(p, re.IGNORECASE) for p in pattern]
            else:
                self.patterns[key] = re.compile(pattern, re.IGNORECASE)
                
    def reset_stats(self):
        """Reset statistics counters"""
        self.stats = {
            'total_lines': 0,
            'total_errors': 0,
            'total_warnings': 0,
            'total_info': 0,
            'error_patterns': defaultdict(int),
            'warning_patterns': defaultdict(int),
            'response_times': [],
            'status_codes': defaultdict(int),
            'endpoints': defaultdict(int),
            'timestamps': []
        }
        
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line"""
        if not line.strip():
            return None
            
        entry = LogEntry(
            timestamp=None,
            level='UNKNOWN',
            message=line.strip(),
            raw_line=line
        )
        
        try:
            # Extract timestamp
            timestamp_match = self.patterns['timestamp'].search(line)
            if timestamp_match:
                try:
                    entry.timestamp = datetime.fromisoformat(
                        timestamp_match.group(1).replace(' ', 'T')
                    )
                except ValueError:
                    self.logger.debug(f"Could not parse timestamp: {timestamp_match.group(1)}")
                    
            # Extract log level
            level_match = self.patterns['level'].search(line)
            if level_match:
                entry.level = level_match.group(1).upper()
                
            # Extract response time
            response_time_match = self.patterns['response_time'].search(line)
            if response_time_match:
                entry.response_time = float(response_time_match.group(1))
                
            # Extract status code
            status_code_match = self.patterns['status_code'].search(line)
            if status_code_match:
                entry.status_code = int(status_code_match.group(1))
                
            # Extract endpoint
            endpoint_match = self.patterns['endpoint'].search(line)
            if endpoint_match:
                entry.endpoint = endpoint_match.group(1)
                
        except Exception as e:
            self.logger.warning(f"Error parsing line: {e}")
            
        return entry
        
    def analyze_entry(self, entry: LogEntry):
        """Analyze a single log entry and update statistics"""
        self.stats['total_lines'] += 1
        
        # Count log levels
        if 'ERROR' in entry.level or 'FATAL' in entry.level or 'CRITICAL' in entry.level:
            self.stats['total_errors'] += 1
            # Check for specific error patterns
            for pattern in self.patterns['error_patterns']:
                if pattern.search(entry.raw_line):
                    pattern_str = pattern.pattern
                    self.stats['error_patterns'][pattern_str] += 1
                    
        elif 'WARN' in entry.level:
            self.stats['total_warnings'] += 1
            # Check for specific warning patterns
            for pattern in self.patterns['warning_patterns']:
                if pattern.search(entry.raw_line):
                    pattern_str = pattern.pattern
                    self.stats['warning_patterns'][pattern_str] += 1
                    
        elif 'INFO' in entry.level:
            self.stats['total_info'] += 1
            
        # Collect performance metrics
        if entry.response_time is not None:
            self.stats['response_times'].append(entry.response_time)
            
        if entry.status_code is not None:
            self.stats['status_codes'][entry.status_code] += 1
            
        if entry.endpoint:
            self.stats['endpoints'][entry.endpoint] += 1
            
        if entry.timestamp:
            self.stats['timestamps'].append(entry.timestamp)
            
    def calculate_percentile(self, data: List[float], percentile: float) -> Optional[float]:
        """Calculate percentile value from a list of numbers"""
        if not data:
            return None
            
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        
        if index >= len(sorted_data):
            return sorted_data[-1]
        return sorted_data[index]
        
    def generate_report(self) -> LogAnalysisReport:
        """Generate analysis report from collected statistics"""
        # Calculate response time metrics
        avg_response_time = None
        p95_response_time = None
        p99_response_time = None
        
        if self.stats['response_times']:
            avg_response_time = sum(self.stats['response_times']) / len(self.stats['response_times'])
            p95_response_time = self.calculate_percentile(self.stats['response_times'], 95)
            p99_response_time = self.calculate_percentile(self.stats['response_times'], 99)
            
        # Get top endpoints
        top_endpoints = sorted(
            self.stats['endpoints'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # Determine time range
        time_range = (None, None)
        if self.stats['timestamps']:
            time_range = (min(self.stats['timestamps']), max(self.stats['timestamps']))
            
        return LogAnalysisReport(
            total_lines=self.stats['total_lines'],
            total_errors=self.stats['total_errors'],
            total_warnings=self.stats['total_warnings'],
            total_info=self.stats['total_info'],
            error_patterns=dict(self.stats['error_patterns']),
            warning_patterns=dict(self.stats['warning_patterns']),
            avg_response_time=avg_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            status_codes=dict(self.stats['status_codes']),
            top_endpoints=top_endpoints,
            time_range=time_range
        )
        
    def analyze_file(self, file_path: Path) -> LogAnalysisReport:
        """Analyze a log file"""
        self.reset_stats()
        self.logger.info(f"Starting analysis of {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        entry = self.parse_line(line)
                        if entry:
                            self.analyze_entry(entry)
                            
                        # Log progress every 10000 lines
                        if line_num % 10000 == 0:
                            self.logger.info(f"Processed {line_num} lines")
                            
                    except Exception as e:
                        self.logger.error(f"Error processing line {line_num}: {e}")
                        continue
                        
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            raise
        except Exception as e:
            self.logger.error(f"Error reading file: {e}")
            raise
            
        self.logger.info(f"Analysis complete. Processed {self.stats['total_lines']} lines")
        return self.generate_report()
        
    def analyze_files(self, file_paths: List[Path]) -> LogAnalysisReport:
        """Analyze multiple log files"""
        self.reset_stats()
        
        for file_path in file_paths:
            self.logger.info(f"Analyzing {file_path}")
            try:
                # Analyze each file but accumulate stats
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        entry = self.parse_line(line)
                        if entry:
                            self.analyze_entry(entry)
            except Exception as e:
                self.logger.error(f"Error analyzing {file_path}: {e}")
                continue
                
        return self.generate_report()


def load_config(config_file: Optional[str]) -> Dict[str, Any]:
    """Load configuration from file"""
    config = {}
    
    if config_file and Path(config_file).exists():
        parser = configparser.ConfigParser()
        parser.read(config_file)
        
        # Convert ConfigParser to dict
        for section in parser.sections():
            config[section] = dict(parser.items(section))
            
        # Parse patterns if they exist
        if 'patterns' in config:
            patterns_section = config['patterns']
            if 'error_patterns' in patterns_section:
                patterns_section['error_patterns'] = json.loads(patterns_section['error_patterns'])
            if 'warning_patterns' in patterns_section:
                patterns_section['warning_patterns'] = json.loads(patterns_section['warning_patterns'])
                
    return config


def format_report(report: LogAnalysisReport, format_type: str = 'text') -> str:
    """Format the report for output"""
    if format_type == 'json':
        return json.dumps(report.to_dict(), indent=2, default=str)
        
    # Text format
    lines = []
    lines.append("=" * 80)
    lines.append("LOG ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"\nSummary:")
    lines.append(f"  Total lines processed: {report.total_lines:,}")
    lines.append(f"  Errors: {report.total_errors:,}")
    lines.append(f"  Warnings: {report.total_warnings:,}")
    lines.append(f"  Info: {report.total_info:,}")
    
    if report.time_range[0] and report.time_range[1]:
        lines.append(f"\nTime Range:")
        lines.append(f"  Start: {report.time_range[0]}")
        lines.append(f"  End: {report.time_range[1]}")
        duration = report.time_range[1] - report.time_range[0]
        lines.append(f"  Duration: {duration}")
        
    if report.error_patterns:
        lines.append(f"\nTop Error Patterns:")
        for pattern, count in sorted(report.error_patterns.items(), key=lambda x: x[1], reverse=True)[:10]:
            lines.append(f"  {pattern}: {count}")
            
    if report.warning_patterns:
        lines.append(f"\nTop Warning Patterns:")
        for pattern, count in sorted(report.warning_patterns.items(), key=lambda x: x[1], reverse=True)[:10]:
            lines.append(f"  {pattern}: {count}")
            
    if report.avg_response_time is not None:
        lines.append(f"\nPerformance Metrics:")
        lines.append(f"  Average Response Time: {report.avg_response_time:.2f}ms")
        lines.append(f"  P95 Response Time: {report.p95_response_time:.2f}ms")
        lines.append(f"  P99 Response Time: {report.p99_response_time:.2f}ms")
        
    if report.status_codes:
        lines.append(f"\nHTTP Status Codes:")
        for code, count in sorted(report.status_codes.items()):
            lines.append(f"  {code}: {count:,}")
            
    if report.top_endpoints:
        lines.append(f"\nTop 10 Endpoints:")
        for endpoint, count in report.top_endpoints:
            lines.append(f"  {endpoint}: {count:,}")
            
    lines.append("\n" + "=" * 80)
    return "\n".join(lines)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Analyze application logs for errors, warnings, and performance metrics'
    )
    parser.add_argument(
        'files',
        nargs='+',
        help='Log file(s) to analyze'
    )
    parser.add_argument(
        '-c', '--config',
        help='Configuration file path'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file path (default: stdout)'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level for the analyzer (default: INFO)'
    )
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Override log level if specified in command line
        if args.log_level:
            config['log_level'] = args.log_level
            
        # Create analyzer
        analyzer = LogAnalyzer(config)
        
        # Convert file paths
        file_paths = [Path(f) for f in args.files]
        
        # Check if files exist
        for file_path in file_paths:
            if not file_path.exists():
                logging.error(f"File not found: {file_path}")
                sys.exit(1)
                
        # Analyze files
        if len(file_paths) == 1:
            report = analyzer.analyze_file(file_paths[0])
        else:
            report = analyzer.analyze_files(file_paths)
            
        # Format report
        output = format_report(report, args.format)
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Report written to {args.output}")
        else:
            print(output)
            
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
