# End Point Inspector (EPI)

## Introduction

End Point Inspector (EPI) is a powerful API endpoint discovery and generalization tool designed to help developers, security teams, and system administrators analyze HTTP traffic patterns and identify API endpoints from raw HTTP messages. EPI automatically clusters and generalizes URLs using advanced pattern recognition algorithms, making it particularly valuable for applications with variable parameters in URL paths.

The tool provides intelligent endpoint generalization through two primary approaches:
- **Adaptive Generalization**: Uses semantic pattern detection with entropy analysis to identify and label common patterns like JWTs, UUIDs, Base64 tokens, and numeric sequences
- **Drain3-based Generalization**: Leverages the proven Drain algorithm for template mining with enhanced masking patterns and post-processing

## Features

- **Dual Generalization Modes**: 
  - Adaptive generalization with intelligent pattern detection (JWT, Base64, UUID, numeric patterns)
  - Drain3-based template mining with enhanced masking and clustering
- **Multiple Output Formats**: Tree structure, JSON, and XML output formats for different integration needs
- **Recursive File Processing**: Automatically processes all HTTP message files in nested directory structures
- **High Performance**: Capable of handling thousands of HTTP messages efficiently with streaming processing
- **Modular Architecture**: Clean separation of concerns with dedicated generalizer package
- **Pattern Recognition**: Advanced entropy analysis and semantic labeling for common token patterns
- **Template Mining**: Drain algorithm implementation with manual masking patterns and intelligent merging
- **CLI Interface**: Comprehensive command-line interface with flexible input/output options
- **Easy Integration**: Designed for seamless integration with proxy software, WAFs, and security tools

## Dependencies

EPI relies on several key dependencies to provide its endpoint discovery and generalization capabilities:

### Python Packages (pip installable)

#### Core Dependencies
- **drain3** - IBM's implementation of the Drain algorithm for log template mining
  - *Purpose*: Powers the Drain3-based generalization mode for clustering similar URL patterns
  - *Usage*: Template mining, pattern detection, and intelligent URL clustering with configurable similarity thresholds
  - *Installation*: `pip install drain3`

- **llhttp** - Python bindings for the llhttp HTTP parser (Node.js's HTTP parser)
  - *Purpose*: High-performance parsing of raw HTTP messages to extract URL, method, and header information
  - *Usage*: Parses HTTP request/response data from proxy logs, WAF logs, or captured network traffic
  - *Installation*: `pip install llhttp`
  - *Note*: Provides significantly better performance than pure Python HTTP parsing libraries

#### Standard Library Dependencies
The tool leverages several Python standard library modules:
- **argparse** - Command-line argument parsing and help generation
- **glob** - Recursive file pattern matching for testdata processing
- **re** - Regular expression pattern matching for adaptive generalization
- **os** - File system operations and path handling
- **sys** - System-specific parameters and functions
- **json** - JSON output formatting
- **xml.etree.ElementTree** - XML output formatting

### Development Environment Dependencies

#### Virtual Environment (Recommended)
- **venv** - Python's built-in virtual environment tool
  - *Purpose*: Isolates project dependencies from system Python packages
  - *Usage*: Prevents version conflicts and ensures reproducible installations
  - *Setup*: 
    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/macOS
    # or
    venv\Scripts\activate.bat  # Windows
    ```

#### Python Runtime
- **Python 3.7+** - Minimum required Python version
  - *Features Used*: F-strings, pathlib, type hints, dataclasses (optional)
  - *Recommended*: Python 3.9+ for optimal performance and feature support

### External Tool Integration (Optional)

EPI is designed to integrate with various security and networking tools:

- **Web Application Firewalls (WAFs)** - Can process HTTP logs from ModSecurity, AWS WAF, etc.
- **Proxy Servers** - Integrates with Nginx, Apache, Squid proxy logs
- **API Gateways** - Works with Kong, AWS API Gateway, Azure API Management logs
- **Network Capture Tools** - Can process HTTP traffic from tcpdump, Wireshark exports
- **Security Tools** - Integrates with Burp Suite exports, OWASP ZAP logs

### Installation Dependencies Summary

For a complete installation, you'll need:
```bash
# System requirements
Python 3.7 or higher

# Python packages (from requirements.txt)
pip install llhttp drain3

# Optional: Development tools
pip install pytest  # For testing
pip install black   # For code formatting
```

## Building and Running

### Prerequisites
- Python 3.7 or higher
- Required Python packages (see `requirements.txt`)
- Virtual environment (recommended)

### Installation
1. Clone or download the repository
2. Create virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Make script executable (optional):
   ```bash
   chmod +x epi.py
   ```

### Usage

#### Getting Help
By default, running epi.py without arguments displays help information:
```bash
./epi.py
# or
python epi.py
```

#### Basic Usage
Process test data files with adaptive generalization:
```bash
./epi.py --testdata
```

#### Command Line Options
The tool provides comprehensive command-line options accessible via help:
```bash
./epi.py --help
```

Key options include:
- `--testdata` - Process all testdata files (testdata/**/*.txt)
- `-if INPUT_FILE` - Specify custom input file containing HTTP messages  
- `-out FORMAT` - Output format: tree (default), json, xml
- `-of OUTPUT_FILE` - Write results to file (default: stdout)
- `--drain3-only` - Use only Drain3 algorithm (disable adaptive patterns)
- `--drain3-similarity THRESHOLD` - Drain3 clustering sensitivity (0.0-1.0)
- `--drain3-depth DEPTH` - Drain3 tree depth for pattern matching

#### Examples

**Show Help (Default Behavior)**:
```bash
./epi.py
```

**Process Test Data with Adaptive Generalization**:
```bash
./epi.py --testdata
```

**Process Custom File**:
```bash
./epi.py -if custom_http_messages.txt
```

**Drain3-Only Mode with Test Data**:
```bash
./epi.py --testdata --drain3-only
```

**JSON Output to File**:
```bash
./epi.py --testdata -out json -of results.json
```

**Custom File with Advanced Options**:
```bash
./epi.py -if logs.txt --drain3-only --drain3-similarity 0.2 -out xml -of endpoints.xml
```

### Input Format
HTTP messages should be in raw HTTP format:
```
GET /api/users/12345 HTTP/1.1
Host: example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

POST /api/auth HTTP/1.1
Host: example.com
Content-Type: application/json
```

## Testing

### Test Data Structure
The project includes comprehensive test data organized by categories:
```
testdata/
├── category_a/*.txt
├── category_b/*.txt  
├── category_c/*.txt
└── category_d/*.txt
```

### Running Tests
Execute the script with the testdata flag to test all sample data:
```bash
./epi.py --testdata
```

### Validation
The tool processes test data and outputs generalized endpoints. Example output:
- **Adaptive Mode**: `/api/users/{UUID}`, `/auth/token/{JWT}`, `/data/{BASE64-JSON}`
- **Drain3 Mode**: `/api/users/{*}`, `/auth/token/{*}`, `/data/{*}`

### Custom Testing  
To test with your own HTTP message files:
1. Create files with raw HTTP messages
2. Run: `./epi.py -if your_http_message_file.txt`
3. Verify generalization accuracy for your specific use case

### Help and Documentation
For comprehensive usage information:
```bash
./epi.py --help
```

## Current Development Status

### Completed Features
- ✅ **Modular Architecture**: Complete refactoring with separated generalizer package
- ✅ **Dual Generalization Modes**: Both adaptive and Drain3-based approaches implemented
- ✅ **Pattern Recognition**: JWT, Base64, UUID, and numeric pattern detection
- ✅ **Multiple Output Formats**: Tree, JSON, and XML output support
- ✅ **CLI Interface**: Comprehensive command-line argument processing
- ✅ **Recursive Processing**: Enhanced default behavior for processing all test data
- ✅ **Template Mining**: Drain3 integration with custom masking and post-processing

### Architecture Overview
```
epi/
├── generalizer/              # Core generalization package
│   ├── __init__.py          # Package exports
│   ├── base.py              # Abstract Generalizer base class
│   ├── adaptive.py          # Semantic pattern detection
│   └── drain.py             # Drain3-based template mining
├── epi.py                   # Main executable script
├── testdata/                # Sample HTTP message data
└── requirements.txt         # Python dependencies
```

### Future Enhancements
- 🔄 **Performance Optimization**: Enhanced caching and memory management
- 🔄 **Advanced Pattern Detection**: Extended semantic pattern recognition
- 🔄 **Real-time Processing**: Streaming analysis capabilities
- 🔄 **Integration APIs**: REST API interface for external tool integration
- 🔄 **Security Focus**: Enhanced security-specific pattern detection
- 🔄 **Visualization**: Web-based dashboard for endpoint analysis

### Contributing
The project follows a clean, modular architecture making it easy to:
- Add new generalization algorithms by extending the `Generalizer` base class
- Implement additional output formats
- Enhance pattern recognition capabilities
- Integrate with external security tools

### Maintenance Status
- **Active Development**: Core functionality complete and stable
- **Testing**: Comprehensive validation across multiple HTTP message types
- **Documentation**: Complete API documentation and usage examples
- **Compatibility**: Python 3.7+ with standard library dependencies