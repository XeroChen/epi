#!/usr/bin/env python3
"""
PCAP Parser - Extract HTTP request messages from pcap/pcapng files.

This module uses scapy to parse pcap files and extract HTTP request messages
in a format compatible with the epi tool.
"""

import os
import sys
from typing import List, Optional, Dict, Any, Generator

try:
    from scapy.all import rdpcap, TCP, IP, IPv6, Raw
    from scapy.layers.http import HTTPRequest, HTTP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import llhttp
    LLHTTP_AVAILABLE = True
except ImportError:
    LLHTTP_AVAILABLE = False


class LLHTTPRequestParser(llhttp.Request if LLHTTP_AVAILABLE else object):
    """Callback-based HTTP request parser using llhttp."""
    
    def __init__(self):
        if LLHTTP_AVAILABLE:
            super().__init__()
        self.reset_state()
    
    def reset_state(self):
        """Reset parser state for a new request."""
        self._method = b""
        self._url = b""
        self._version_major = 0
        self._version_minor = 0
        self._headers: List[tuple] = []
        self._body = b""
        self._current_header_field = None
        self._current_header_value = None
        self._message_complete = False
    
    def on_message_begin(self):
        """Called when a new message starts."""
        self.reset_state()
    
    def on_method(self, method: bytes):
        """Called with HTTP method."""
        self._method = method
    
    def on_url(self, url: bytes):
        """Called with URL (may be called multiple times)."""
        self._url += url
    
    def on_header_field(self, field: bytes):
        """Called with header field name."""
        # Save previous header if exists
        if self._current_header_value is not None:
            self._headers.append((
                self._current_header_field.decode('iso-8859-1', errors='replace'),
                self._current_header_value.decode('iso-8859-1', errors='replace')
            ))
            self._current_header_value = None
        
        if self._current_header_field is None:
            self._current_header_field = bytearray(field)
        else:
            self._current_header_field += field
    
    def on_header_field_complete(self):
        """Called when header field is complete."""
        pass
    
    def on_header_value(self, value: bytes):
        """Called with header value."""
        if self._current_header_value is None:
            self._current_header_value = bytearray(value)
        else:
            self._current_header_value += value
    
    def on_header_value_complete(self):
        """Called when header value is complete."""
        if self._current_header_field is not None and self._current_header_value is not None:
            self._headers.append((
                bytes(self._current_header_field).decode('iso-8859-1', errors='replace'),
                bytes(self._current_header_value).decode('iso-8859-1', errors='replace')
            ))
            self._current_header_field = None
            self._current_header_value = None
    
    def on_headers_complete(self):
        """Called when all headers are complete."""
        self._version_major = self.major
        self._version_minor = self.minor
    
    def on_body(self, body: bytes):
        """Called with body data."""
        self._body += body
    
    def on_message_complete(self):
        """Called when message is complete."""
        self._message_complete = True
    
    def parse(self, data: bytes) -> bool:
        """
        Parse HTTP request data.
        
        Args:
            data: Raw HTTP request bytes
            
        Returns:
            True if parsing succeeded, False otherwise
        """
        self.reset_state()
        self.reset()
        
        try:
            self.execute(data)
            self.finish()
            return not self.is_busted
        except Exception:
            return False
    
    def get_method(self) -> str:
        """Get HTTP method."""
        # First try our captured method from on_method callback
        if self._method:
            if isinstance(self._method, memoryview):
                return bytes(self._method).decode('utf-8', errors='replace')
            if isinstance(self._method, bytes):
                return self._method.decode('utf-8', errors='replace')
            return str(self._method)
        
        # Fallback to llhttp's method property (may be memoryview)
        method = self.method
        if method:
            if isinstance(method, memoryview):
                return bytes(method).decode('utf-8', errors='replace')
            if isinstance(method, bytes):
                return method.decode('utf-8', errors='replace')
            return str(method)
        
        return ""
    
    def get_url(self) -> str:
        """Get URL."""
        if isinstance(self._url, bytes):
            return self._url.decode('utf-8', errors='replace')
        return self._url or ""
    
    def get_http_version(self) -> str:
        """Get formatted HTTP version string."""
        if self._version_major or self._version_minor:
            return f"HTTP/{self._version_major}.{self._version_minor}"
        return "HTTP/1.1"
    
    def to_message(self) -> Optional[str]:
        """
        Convert parsed request to HTTP message string.
        
        Returns:
            Formatted HTTP request message or None if parsing failed
        """
        method = self.get_method()
        url = self.get_url()
        
        if not method or not url:
            return None
        
        # Build request line
        request_line = f"{method} {url} {self.get_http_version()}"
        
        # Build headers
        header_lines = [f"{name}: {value}" for name, value in self._headers]
        
        # Combine message
        message = request_line
        if header_lines:
            message += "\n" + "\n".join(header_lines)
        
        # Add body if present
        if self._body:
            try:
                body_str = self._body.decode('utf-8', errors='replace').strip()
                if body_str:
                    message += "\n\n" + body_str
            except Exception:
                pass
        
        return message
    
    def get_host(self) -> Optional[str]:
        """
        Get the Host header value from the parsed request.
        
        Returns:
            The Host header value or None if not found
        """
        for name, value in self._headers:
            if name.lower() == 'host':
                return value
        return None


class PcapParser:
    """Parser for extracting HTTP requests from pcap/pcapng files."""
    
    # Message delimiter (same format as testdata files)
    DELIMITER = "\n\n" + "=" * 40 + "\n\n"
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the PCAP parser.
        
        Args:
            verbose: If True, print detailed parsing information
        """
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy is required for pcap parsing. "
                "Install it with: pip install scapy"
            )
        if not LLHTTP_AVAILABLE:
            raise ImportError(
                "llhttp is required for HTTP parsing. "
                "Install it with: pip install llhttp"
            )
        self.verbose = verbose
        self._requests: List[str] = []
        self._requests_by_host: Dict[str, List[str]] = {}  # Group requests by Host header
        self._llhttp_parser = LLHTTPRequestParser()
    
    def parse_file(self, filepath: str) -> List[str]:
        """
        Parse a pcap/pcapng file and extract HTTP request messages.
        
        Args:
            filepath: Path to the pcap or pcapng file
            
        Returns:
            List of HTTP request messages as strings
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        
        self._requests = []
        self._requests_by_host = {}
        
        if self.verbose:
            print(f"Parsing PCAP file: {filepath}")
        
        try:
            packets = rdpcap(filepath)
        except Exception as e:
            raise ValueError(f"Failed to read PCAP file: {e}")
        
        # Track TCP streams for reassembly
        tcp_streams: Dict[tuple, bytes] = {}
        
        for packet in packets:
            self._process_packet(packet, tcp_streams)
        
        # Process any remaining data in TCP streams
        for stream_data in tcp_streams.values():
            self._try_parse_http(stream_data)
        
        if self.verbose:
            print(f"Extracted {len(self._requests)} HTTP requests")
        
        return self._requests
    
    def _get_stream_key(self, packet) -> Optional[tuple]:
        """Get a unique key for a TCP stream."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return None
        
        if TCP not in packet:
            return None
        
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        # Normalize stream key (always use smaller IP:port first)
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port)
        else:
            return (dst_ip, dst_port, src_ip, src_port)
    
    def _process_packet(self, packet, tcp_streams: Dict[tuple, bytes]):
        """Process a single packet and extract HTTP request if present."""
        # Check if packet has HTTP layer (scapy's HTTP dissector)
        if HTTPRequest in packet:
            self._extract_http_request(packet)
            return
        
        # Try to extract from raw TCP payload
        if TCP in packet and Raw in packet:
            payload = bytes(packet[Raw].load)
            
            # Check if this looks like an HTTP request
            if self._is_http_request(payload):
                self._try_parse_http(payload)
            else:
                # Accumulate in TCP stream for reassembly
                stream_key = self._get_stream_key(packet)
                if stream_key:
                    if stream_key not in tcp_streams:
                        tcp_streams[stream_key] = b''
                    tcp_streams[stream_key] += payload
                    
                    # Try to parse accumulated data
                    if self._is_http_request(tcp_streams[stream_key]):
                        self._try_parse_http(tcp_streams[stream_key])
                        tcp_streams[stream_key] = b''
    
    def _is_http_request(self, data: bytes) -> bool:
        """Check if data starts with an HTTP request method."""
        if not data:
            return False
        
        http_methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'PATCH ', 
                        b'HEAD ', b'OPTIONS ', b'TRACE ', b'CONNECT ']
        
        return any(data.startswith(method) for method in http_methods)
    
    def _extract_http_request(self, packet):
        """Extract HTTP request from a packet using llhttp parser."""
        try:
            # Get raw HTTP data from packet
            if Raw in packet:
                raw_data = bytes(packet[Raw].load)
            else:
                # Try to reconstruct from HTTPRequest layer
                http_layer = packet[HTTPRequest]
                
                # Build raw HTTP request from scapy's parsed data
                # Note: scapy may return memoryview objects, so convert to bytes
                method = http_layer.Method if http_layer.Method else b'GET'
                if isinstance(method, memoryview):
                    method = bytes(method)
                elif isinstance(method, str):
                    method = method.encode()
                    
                path = http_layer.Path if http_layer.Path else b'/'
                if isinstance(path, memoryview):
                    path = bytes(path)
                elif isinstance(path, str):
                    path = path.encode()
                    
                version = http_layer.Http_Version if http_layer.Http_Version else b'HTTP/1.1'
                if isinstance(version, memoryview):
                    version = bytes(version)
                elif isinstance(version, str):
                    version = version.encode()
                
                raw_data = method + b' ' + path + b' ' + version + b'\r\n'
                
                # Add headers - also handle memoryview
                if http_layer.Host:
                    host = http_layer.Host
                    if isinstance(host, memoryview):
                        host = bytes(host)
                    elif isinstance(host, str):
                        host = host.encode()
                    raw_data += b'Host: ' + host + b'\r\n'
                
                # Add other headers from fields
                header_fields = [
                    ('User_Agent', b'User-Agent'),
                    ('Accept', b'Accept'),
                    ('Accept_Language', b'Accept-Language'),
                    ('Accept_Encoding', b'Accept-Encoding'),
                    ('Content_Type', b'Content-Type'),
                    ('Content_Length', b'Content-Length'),
                    ('Authorization', b'Authorization'),
                    ('Cookie', b'Cookie'),
                    ('Connection', b'Connection'),
                    ('Cache_Control', b'Cache-Control'),
                    ('Referer', b'Referer'),
                    ('Origin', b'Origin'),
                ]
                
                for field_name, header_name in header_fields:
                    value = getattr(http_layer, field_name, None)
                    if value:
                        if isinstance(value, memoryview):
                            value = bytes(value)
                        elif isinstance(value, str):
                            value = value.encode()
                        raw_data += header_name + b': ' + value + b'\r\n'
                
                raw_data += b'\r\n'
            
            # Parse using llhttp
            if self._llhttp_parser.parse(raw_data):
                message = self._llhttp_parser.to_message()
                if message:
                    host = self._llhttp_parser.get_host()
                    self._add_request(message, host)
                    
                    if self.verbose:
                        print(f"  Extracted: {self._llhttp_parser.get_method()} {self._llhttp_parser.get_url()}")
            else:
                if self.verbose:
                    print(f"  llhttp parse failed, error: {self._llhttp_parser.error}")
                
        except Exception as e:
            if self.verbose:
                print(f"  Error extracting HTTP request: {e}")
    
    def _try_parse_http(self, data: bytes):
        """Try to parse raw bytes as an HTTP request using llhttp."""
        try:
            # Parse using llhttp
            if self._llhttp_parser.parse(data):
                message = self._llhttp_parser.to_message()
                if message:
                    host = self._llhttp_parser.get_host()
                    self._add_request(message, host)
                    
                    if self.verbose:
                        print(f"  Parsed: {self._llhttp_parser.get_method()} {self._llhttp_parser.get_url()}")
            # Don't log parse failures for stream data - it may not be HTTP
                
        except Exception as e:
            if self.verbose:
                print(f"  Error parsing HTTP data: {e}")
    
    def _add_request(self, message: str, host: Optional[str]):
        """
        Add a request to the internal storage.
        
        Args:
            message: The HTTP request message string
            host: The Host header value (domain)
        """
        self._requests.append(message)
        
        # Group by host (use 'unknown' if no Host header)
        host_key = host if host else 'unknown'
        if host_key not in self._requests_by_host:
            self._requests_by_host[host_key] = []
        self._requests_by_host[host_key].append(message)
    
    def get_requests(self) -> List[str]:
        """Get the list of extracted HTTP request messages."""
        return self._requests
    
    def get_requests_by_host(self) -> Dict[str, List[str]]:
        """Get the dictionary of HTTP request messages grouped by Host header."""
        return self._requests_by_host
    
    def to_string(self) -> str:
        """
        Convert extracted requests to a string format compatible with epi.
        
        Returns:
            String with all requests separated by delimiter lines
        """
        if not self._requests:
            return ""
        
        return self.DELIMITER.join(self._requests)
    
    def to_string_by_host(self, host: str) -> str:
        """
        Convert extracted requests for a specific host to a string format.
        
        Args:
            host: The Host header value (domain) to get messages for
            
        Returns:
            String with all requests for that host separated by delimiter lines
        """
        if host not in self._requests_by_host:
            return ""
        
        return self.DELIMITER.join(self._requests_by_host[host])
    
    def save_to_file(self, output_path: str):
        """
        Save extracted HTTP requests to a file.
        
        Args:
            output_path: Path to the output file
        """
        content = self.to_string()
        
        with open(output_path, 'w') as f:
            f.write(content)
        
        if self.verbose:
            print(f"Saved {len(self._requests)} requests to {output_path}")
    
    def save_to_files_by_host(self, output_dir: str, filename: str = "http_messages.txt"):
        """
        Save extracted HTTP requests to separate files grouped by Host header (domain).
        
        Creates a directory structure like:
            output_dir/
                domain1.example.com/
                    http_messages.txt
                domain2.example.com/
                    http_messages.txt
                ...
        
        Args:
            output_dir: Base directory to save files to
            filename: Name of the file to create in each domain directory (default: http_messages.txt)
            
        Returns:
            Dict mapping host to the file path where messages were saved
        """
        import re
        
        if not self._requests_by_host:
            if self.verbose:
                print("No requests to save")
            return {}
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        saved_files = {}
        
        for host, messages in self._requests_by_host.items():
            # Sanitize host for use as directory name
            # Replace invalid characters with underscores
            safe_host = re.sub(r'[<>:"/\\|?*]', '_', host)
            # Remove port number for directory name (but keep it recognizable)
            # e.g., "example.com:8080" -> "example.com_8080"
            safe_host = safe_host.replace(':', '_')
            
            # Create directory for this host
            host_dir = os.path.join(output_dir, safe_host)
            os.makedirs(host_dir, exist_ok=True)
            
            # Write messages to file
            file_path = os.path.join(host_dir, filename)
            content = self.DELIMITER.join(messages)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            saved_files[host] = file_path
            
            if self.verbose:
                print(f"Saved {len(messages)} requests to {file_path}")
        
        if self.verbose:
            print(f"Total: Saved requests to {len(saved_files)} files in {output_dir}")
        
        return saved_files


def extract_http_requests(pcap_path: str, 
                          output_path: Optional[str] = None,
                          verbose: bool = False) -> List[str]:
    """
    Convenience function to extract HTTP requests from a pcap file.
    
    Args:
        pcap_path: Path to the pcap/pcapng file
        output_path: Optional path to save the extracted requests
        verbose: If True, print detailed parsing information
        
    Returns:
        List of HTTP request messages as strings
    """
    parser = PcapParser(verbose=verbose)
    requests = parser.parse_file(pcap_path)
    
    if output_path:
        parser.save_to_file(output_path)
    
    return requests


def main():
    """CLI interface for the pcap parser."""
    import argparse
    
    arg_parser = argparse.ArgumentParser(
        description='Extract HTTP request messages from pcap/pcapng files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap                    # Extract and print to stdout
  %(prog)s capture.pcap -o requests.txt    # Save to file
  %(prog)s capture.pcapng -v               # Verbose output
        """
    )
    
    arg_parser.add_argument('pcap_file', 
                           help='Path to pcap or pcapng file')
    
    arg_parser.add_argument('-o', '--output', dest='output_file',
                           help='Output file path (default: stdout)')
    
    arg_parser.add_argument('-v', '--verbose', action='store_true',
                           help='Enable verbose output')
    
    args = arg_parser.parse_args()
    
    try:
        parser = PcapParser(verbose=args.verbose)
        requests = parser.parse_file(args.pcap_file)
        
        if args.output_file:
            parser.save_to_file(args.output_file)
            print(f"Extracted {len(requests)} HTTP requests to {args.output_file}")
        else:
            print(parser.to_string())
            
    except ImportError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
