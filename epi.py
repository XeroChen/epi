#!/usr/bin/env python3
# API Endpoint Discovery Tool
import os
import glob
import argparse
import sys
import re

# Import from our generalizer package
from generalizer import AdaptiveGeneralizer, DrainGeneralizer
from pcap_parser import PcapParser

# Global generalizer instances - will be set in main()
generalizer = None

# --- HTTP Message Parser ---

def parse_http_message(message: str):
    """Parse HTTP message using simple string parsing to extract endpoint information."""
    try:
        lines = message.strip().split('\n')
        if not lines:
            return None
        
        # Parse request line
        request_line = lines[0].strip()
        if not request_line:
            return None
            
        parts = request_line.split()
        if len(parts) < 3:
            return None
            
        method = parts[0].upper()
        url = parts[1]
        version = parts[2]
        
        # Parse headers
        headers = {}
        host = ""
        
        for line in lines[1:]:
            line = line.strip()
            if not line:  # Empty line indicates end of headers
                break
                
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                headers[key] = value
                
                if key == 'host':
                    host = value
        
        if not host:
            # If no Host header, try to extract from URL if it's absolute
            if url.startswith('http'):
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.netloc
                url = parsed.path + ('?' + parsed.query if parsed.query else '')
        
        return {
            'method': method,
            'url': url,
            'version': version,
            'host': host,
            'headers': headers,
            'scheme': 'https'  # Assume HTTPS for API endpoints
        }
        
    except Exception as e:
        print(f"Error parsing HTTP message: {e}")
        return None

def load_http_messages_from_file(filepath):
    """Load and parse HTTP messages from a file."""
    requests = []
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Split messages by delimiter lines (lines starting with '=' and containing at least 5 '=' chars)
        delimiter_pattern = re.compile(r'^=.*={5,}.*$', re.MULTILINE)
        messages = delimiter_pattern.split(content)
        
        for message in messages:
            message = message.strip()
            if not message:
                continue
                
            parsed = parse_http_message(message)
            if parsed and parsed['method'] and parsed['url'] and parsed['host']:
                requests.append(parsed)
    
    except Exception as e:
        print(f"Error loading HTTP messages from {filepath}: {e}")
    
    return requests

def load_http_messages_from_pcap(filepath):
    """Load and parse HTTP messages from a pcap/pcapng file."""
    requests = []
    
    try:
        parser = PcapParser(verbose=False)
        raw_messages = parser.parse_file(filepath)
        
        for message in raw_messages:
            parsed = parse_http_message(message)
            if parsed and parsed['method'] and parsed['url'] and parsed['host']:
                requests.append(parsed)
    
    except Exception as e:
        print(f"Error loading HTTP messages from pcap {filepath}: {e}")
    
    return requests

def load_http_messages_from_input(input_file, use_testdata=False):
    """Load HTTP messages from input file or testdata if specified."""
    all_requests = []
    
    if input_file:
        # Load from specified file
        print(f"Loading HTTP messages from: {input_file}")
        if os.path.exists(input_file):
            # Check file extension to determine parser
            _, ext = os.path.splitext(input_file.lower())
            if ext in ('.pcap', '.pcapng'):
                requests = load_http_messages_from_pcap(input_file)
            else:
                requests = load_http_messages_from_file(input_file)
            all_requests.extend(requests)
            print(f"Loaded {len(requests)} HTTP messages from {input_file}")
        else:
            print(f"Error: Input file {input_file} not found")
            sys.exit(1)
    elif use_testdata:
        # Load from default testdata categories - find all .txt files in testdata/**/
        testdata_base = os.path.join(os.path.dirname(__file__), 'testdata')
        
        print("Loading HTTP messages from testdata...")
        
        # Use glob to find all .txt files recursively in testdata
        txt_files = glob.glob(os.path.join(testdata_base, '**', '*.txt'), recursive=True)
        
        if not txt_files:
            print(f"Warning: No .txt files found in {testdata_base}")
            return all_requests
        
        print(f"Found {len(txt_files)} .txt files in testdata")
        
        for txt_file in sorted(txt_files):
            # Get relative path for display
            rel_path = os.path.relpath(txt_file, testdata_base)
            print(f"Loading {rel_path}...")
            
            requests = load_http_messages_from_file(txt_file)
            all_requests.extend(requests)
            print(f"  Loaded {len(requests)} HTTP messages from {rel_path}")
    
    return all_requests

def main():
    """Main function with CLI interface for API endpoint discovery."""
    global generalizer
    
    parser = argparse.ArgumentParser(
        description='API Endpoint Discovery Tool - Discovers and generalizes API endpoints from HTTP messages',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --help                    # Show this help message
  %(prog)s --testdata                # Process all testdata files with adaptive generalization
  %(prog)s -if data.txt              # Read from custom file
  %(prog)s -if capture.pcap          # Read from pcap file
  %(prog)s --testdata --drain3-only  # Use only Drain3 templates with testdata
  %(prog)s --testdata --drain3-similarity 0.2   # More sensitive Drain3 clustering
  %(prog)s --testdata -out json      # Output testdata results in JSON format
  %(prog)s -if custom.txt -out xml -of results.xml  # Custom file to XML output
  %(prog)s -if custom.txt --drain3-only -out json -of endpoints.json
        """
    )
    
    parser.add_argument('-if', '--input-file', dest='input_file',
                      help='Input file containing HTTP messages (.txt) or packet capture (.pcap, .pcapng)')
    
    parser.add_argument('--testdata', action='store_true',
                      help='Process all testdata files (testdata/**/*.txt)')
    
    parser.add_argument('-out', '--output-format', dest='output_format', 
                      choices=['tree', 'json', 'xml'], default='tree',
                      help='Output format: tree (default), json, or xml')
    
    parser.add_argument('-of', '--output-file', dest='output_file',
                      help='Output file path (default: stdout)')
    
    parser.add_argument('--drain3-only', dest='drain3_only', action='store_true',
                      help='Use only Drain3 for generalization (disable adaptive patterns like JWT, Base64, regex masks)')
    
    parser.add_argument('--drain3-similarity', dest='drain3_similarity', type=float, default=0.8,
                      help='Drain3 similarity threshold (0.0-1.0, lower = more sensitive clustering, default: 0.8)')
    
    parser.add_argument('--drain3-depth', dest='drain3_depth', type=int, default=5,
                      help='Drain3 tree depth (default: 5)')
    
    args = parser.parse_args()
    
    # Show help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    # Check if neither input file nor testdata flag is provided
    if not args.input_file and not args.testdata:
        print("Error: You must specify either --input-file or --testdata")
        parser.print_help()
        sys.exit(1)
    
    # Validate Drain3 similarity threshold
    if not 0.0 <= args.drain3_similarity <= 1.0:
        print("Error: --drain3-similarity must be between 0.0 and 1.0")
        sys.exit(1)
    
    # Configure Drain3 runtime settings
    drain3_config = {
        'similarity_threshold': args.drain3_similarity,
        'depth': args.drain3_depth,
        'max_children': 100,
        'max_clusters': 1024,
        'extra_delimiters': ["/", "?", "&", "="]
    }
    
    # Initialize the appropriate generalizer
    if args.drain3_only:
        generalizer = DrainGeneralizer(drain3_config)
        print("Mode: Drain3 Template Mining only")
    else:
        generalizer = AdaptiveGeneralizer()
        print("Mode: Adaptive Generalization")
    
    # Load HTTP messages
    all_requests = load_http_messages_from_input(args.input_file, args.testdata)
    
    print(f"\nTotal HTTP messages loaded: {len(all_requests)}")
    
    if not all_requests:
        print("No HTTP messages found. Please check your input files.")
        sys.exit(1)
    
    # Process all HTTP requests
    print("\nProcessing HTTP requests...")
    for request in all_requests:
        # Add to endpoints using the streaming interface (add_request processes and stores)
        signature = generalizer.add_request(
            request['host'],
            request['scheme'], 
            request['method'],
            request['url'],
            request['version']
        )
        
        if not args.output_file:  # Only print progress if outputting to stdout
            print(f"Added: {signature}")
    
    # Generate output using the generalizer's output method
    output = generalizer.output(args.output_format)
    
    # Write output to file or stdout
    if args.output_file:
        try:
            with open(args.output_file, 'w') as f:
                f.write(output)
            print(f"\nResults written to: {args.output_file}")
        except Exception as e:
            print(f"Error writing to output file {args.output_file}: {e}")
            sys.exit(1)
    else:
        print("\n" + output)

if __name__ == "__main__":
    main()