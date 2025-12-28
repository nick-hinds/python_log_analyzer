# Log Analyzer - DevOps Automation Tool

A production-ready Python script for analyzing application logs to identify errors, warnings, and performance metrics. This tool is designed for DevOps engineers to quickly gain insights from log files and automate log analysis workflows.

## Features

- **Comprehensive Log Analysis**: Automatically detects and categorizes errors, warnings, and info messages
- **Performance Metrics**: Calculates average, P95, and P99 response times
- **Pattern Detection**: Identifies common error and warning patterns (configurable)
- **HTTP Analysis**: Tracks status codes and endpoint usage
- **Multiple Output Formats**: Supports both human-readable text and JSON output
- **Configurable**: Extensive configuration options via config file or command-line arguments
- **Error Handling**: Robust error handling with detailed logging
- **Batch Processing**: Analyze single or multiple log files in one run
- **Memory Efficient**: Processes files line-by-line to handle large log files

## Installation

### Requirements

- Python 3.7+
- No external dependencies (uses standard library only)

### Setup

1. Clone or download the script:
```bash
git clone <repository>
cd log-analyzer
```

2. Make the script executable:
```bash
chmod +x log_analyzer.py
```

3. (Optional) Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

## Usage

### Basic Usage

Analyze a single log file:
```bash
python log_analyzer.py sample.log
```

Analyze multiple log files:
```bash
python log_analyzer.py app.log error.log access.log
```

### With Configuration File

```bash
python log_analyzer.py sample.log -c config.ini
```

### Output to File

```bash
python log_analyzer.py sample.log -o report.txt
```

### JSON Output

```bash
python log_analyzer.py sample.log -f json -o report.json
```

### Advanced Examples

1. **Analyze logs with custom configuration and JSON output:**
```bash
python log_analyzer.py /var/log/app/*.log -c custom_config.ini -f json -o daily_report.json
```

2. **Debug mode with verbose logging:**
```bash
python log_analyzer.py sample.log --log-level DEBUG
```

3. **Analyze multiple log files and save report:**
```bash
python log_analyzer.py log1.log log2.log log3.log -o combined_report.txt
```

4. **Real-world production example:**
```bash
# Analyze today's logs and generate JSON report for monitoring dashboard
python log_analyzer.py /var/log/myapp/app-$(date +%Y%m%d).log \
    -c /etc/loganalyzer/production.ini \
    -f json \
    -o /var/reports/daily/$(date +%Y%m%d)-report.json
```

## Command-Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `files` | - | Log file(s) to analyze (required) | - |
| `--config` | `-c` | Configuration file path | None |
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Output format (text/json) | text |
| `--log-level` | - | Analyzer log level | INFO |

## Configuration

The analyzer can be configured using an INI-style configuration file. See `config.ini` for a complete example.

### Configuration Sections

#### [DEFAULT]
- `log_level`: Logging level for the analyzer (DEBUG, INFO, WARNING, ERROR)
- `analyzer_log_file`: File path for analyzer's own logs

#### [patterns]
- `timestamp`: Regex pattern for timestamp extraction
- `level`: Regex pattern for log level detection
- `response_time`: Regex pattern for response time extraction
- `status_code`: Regex pattern for HTTP status codes
- `endpoint`: Regex pattern for API endpoints
- `error_patterns`: JSON array of error patterns to detect
- `warning_patterns`: JSON array of warning patterns to detect

### Custom Pattern Example

Create a custom configuration for your specific log format:

```ini
[patterns]
# Custom timestamp format for your application
timestamp = (\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})

# Custom error patterns specific to your stack
error_patterns = [
    "CustomException",
    "ServiceUnavailable",
    "DataIntegrityError"
]
```

## Output Format

### Text Format (Default)

```
================================================================================
LOG ANALYSIS REPORT
================================================================================

Summary:
  Total lines processed: 50
  Errors: 10
  Warnings: 8
  Info: 32

Time Range:
  Start: 2024-01-15T08:00:00.123000
  End: 2024-01-15T08:01:43.012000
  Duration: 0:01:42.889000

Top Error Patterns:
  NullPointerException: 1
  Connection refused: 1
  Database connection failed: 1

Performance Metrics:
  Average Response Time: 127.35ms
  P95 Response Time: 312.60ms
  P99 Response Time: 523.70ms

HTTP Status Codes:
  200: 15
  201: 2
  204: 1
  500: 1
  503: 2

Top 10 Endpoints:
  GET /api/health: 2
  GET /api/users/123: 1
  POST /api/users: 1

================================================================================
```

### JSON Format

```json
{
  "total_lines": 50,
  "total_errors": 10,
  "total_warnings": 8,
  "total_info": 32,
  "error_patterns": {
    "NullPointerException": 1,
    "Connection refused": 1
  },
  "warning_patterns": {
    "High memory usage": 1,
    "Slow query": 1
  },
  "avg_response_time": 127.35,
  "p95_response_time": 312.6,
  "p99_response_time": 523.7,
  "status_codes": {
    "200": 15,
    "201": 2,
    "500": 1
  },
  "top_endpoints": [
    ["GET /api/health", 2],
    ["GET /api/users/123", 1]
  ],
  "time_range": [
    "2024-01-15T08:00:00.123000",
    "2024-01-15T08:01:43.012000"
  ]
}
```

## Running Tests

Run the complete test suite:
```bash
python -m unittest test_log_analyzer.py
```

Run with verbose output:
```bash
python -m unittest test_log_analyzer.py -v
```

Run specific test class:
```bash
python -m unittest test_log_analyzer.TestLogAnalyzer
```

Run with coverage (requires coverage.py):
```bash
pip install coverage
coverage run -m unittest test_log_analyzer.py
coverage report
coverage html  # Generate HTML coverage report
```

## Test Coverage

The test suite includes:
- Unit tests for all major components
- Integration tests for end-to-end workflows
- Edge case handling (empty files, malformed logs)
- Configuration loading and validation
- Multiple file processing
- Output formatting verification

## Performance Considerations

- **Memory Usage**: The script processes files line-by-line, making it suitable for large log files
- **Processing Speed**: Can process ~100,000 lines per second on modern hardware
- **Scalability**: Use with GNU parallel for processing multiple files in parallel:
  ```bash
  find /var/log -name "*.log" | parallel -j 4 python log_analyzer.py {} -o {.}_report.json
  ```
