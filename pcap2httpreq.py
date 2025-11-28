#!/usr/bin/env python3
"""
PCAP to HTTP Request Converter

Extracts HTTP requests from pcap files and organizes them into directories by domain.
"""

import os
import sys
import argparse
import re
from pcap_parser.parser import PcapParser

def main():
    parser = argparse.ArgumentParser(
        description='Extract HTTP requests from pcap and organize by domain',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-p', '--pcap', dest='pcap_file', required=True,
                       help='Path to the pcap/pcapng file')
    
    parser.add_argument('-dir', '--directory', dest='output_dir', required=True,
                       help='Output directory for extracted messages')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap_file):
        print(f"Error: PCAP file not found: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)
        
    print(f"Parsing PCAP file: {args.pcap_file}")
    
    try:
        # Initialize parser
        pcap_parser = PcapParser(verbose=False)
        
        # Parse file
        pcap_parser.parse_file(args.pcap_file)
        
        # Get requests grouped by host
        requests_by_host = pcap_parser.get_requests_by_host()
        
        if not requests_by_host:
            print("No HTTP requests found in the pcap file.")
            return
            
        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)
        
        total_saved = 0
        files_updated = 0
        
        for host, messages in requests_by_host.items():
            # Sanitize host for use as directory name
            # Replace invalid characters with underscores
            safe_host = re.sub(r'[<>:"/\\|?*]', '_', host)
            # Remove port number for directory name (but keep it recognizable)
            safe_host = safe_host.replace(':', '_')
            
            # Create directory for this host
            host_dir = os.path.join(args.output_dir, safe_host)
            os.makedirs(host_dir, exist_ok=True)
            
            # Define output file path
            file_path = os.path.join(host_dir, "http_messages.txt")
            
            # Prepare content
            content = pcap_parser.DELIMITER.join(messages)
            
            # Check if file exists to determine mode and delimiter prefix
            mode = 'w'
            if os.path.exists(file_path):
                mode = 'a'
                # Add delimiter before new content if appending
                content = pcap_parser.DELIMITER + content
                print(f"Appending to existing file: {file_path}")
            else:
                print(f"Creating new file: {file_path}")
            
            # Write to file
            with open(file_path, mode, encoding='utf-8') as f:
                f.write(content)
                
            total_saved += len(messages)
            files_updated += 1
            
        print(f"\nSummary:")
        print(f"  Total requests saved: {total_saved}")
        print(f"  Files updated/created: {files_updated}")
        print(f"  Output directory: {args.output_dir}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
