"""
Base Generalizer Class

This module contains the abstract base class that defines the interface
for all generalization implementations.
"""

from abc import ABC, abstractmethod
from collections import defaultdict
import json


class Generalizer(ABC):
    """Base interface for all generalization implementations."""
    
    def __init__(self):
        self.endpoints = defaultdict(list)  # signature -> list of raw requests
        self.endpoint_counts = defaultdict(int)
        self.pattern_stats = defaultdict(int)
    
    @abstractmethod
    def process_http_message(self, host: str, scheme: str, method: str, url: str, http_version: str) -> str:
        """Process a single HTTP message and return the generalized endpoint signature."""
        pass
    
    @abstractmethod
    def generalize_path(self, path: str) -> str:
        """Generalize a URL path."""
        pass
    
    @abstractmethod
    def generalize_query_params(self, query_string: str) -> str:
        """Generalize query parameters."""
        pass
    
    def add_request(self, host: str, scheme: str, method: str, url: str, http_version: str) -> str:
        """Add a request and group it by endpoint signature (streaming interface)."""
        signature = self.process_http_message(host, scheme, method, url, http_version)
        
        # Store the raw request for examples
        raw_request = {
            'host': host,
            'scheme': scheme, 
            'method': method,
            'url': url,
            'http_version': http_version
        }
        
        self.endpoints[signature].append(raw_request)
        self.endpoint_counts[signature] += 1
        
        return signature
    
    def get_statistics(self) -> str:
        """Get statistics on pattern detection methods."""
        total = sum(self.pattern_stats.values())
        if total == 0:
            return "No patterns processed yet."
        
        stats_lines = ["", f"{self.__class__.__name__.upper()} GENERALIZATION STATISTICS:"]
        stats_lines.append("="*50)
        
        for method, count in self.pattern_stats.items():
            percentage = (count / total) * 100
            stats_lines.append(f"  {method:<25}: {count:4d} ({percentage:5.1f}%)")
        
        stats_lines.append(f"  {'Total Processed':<25}: {total:4d}")
        return '\n'.join(stats_lines)
    
    def output(self, format_type: str = "tree") -> str:
        """Generate formatted output of discovered endpoints."""
        # For DrainGeneralizer, perform post-processing to merge similar patterns
        if hasattr(self, 'use_drain3') and self.use_drain3:
            self._post_process_drain3_patterns()
            
        if format_type == "json":
            return self._format_json()
        elif format_type == "xml":
            return self._format_xml() 
        else:
            return self._format_tree()
    
    def _format_json(self) -> str:
        """Format discovery results as JSON."""
        result = {
            "summary": {
                "total_unique_endpoints": len(self.endpoints),
                "total_requests_processed": sum(self.endpoint_counts.values())
            },
            "domains": {}
        }
        
        # Organize endpoints by FQDN
        domain_endpoints = defaultdict(list)
        for signature, requests in self.endpoints.items():
            domain = signature.split()[0]  # Extract FQDN from signature
            method_url_version = ' '.join(signature.split()[1:])  # Method + URL + Version
            domain_endpoints[domain].append({
                "endpoint": method_url_version,
                "count": len(requests)
            })
        
        # Add domain data to result
        for domain in sorted(domain_endpoints.keys()):
            result["domains"][domain] = {
                "endpoint_count": len(domain_endpoints[domain]),
                "endpoints": sorted(domain_endpoints[domain], key=lambda x: x["endpoint"])
            }
        
        return json.dumps(result, indent=2)
    
    def _format_xml(self) -> str:
        """Format discovery results as XML."""
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_lines.append('<endpoint_discovery>')
        
        # Summary
        xml_lines.append('  <summary>')
        xml_lines.append(f'    <total_unique_endpoints>{len(self.endpoints)}</total_unique_endpoints>')
        xml_lines.append(f'    <total_requests_processed>{sum(self.endpoint_counts.values())}</total_requests_processed>')
        xml_lines.append('  </summary>')
        
        # Domains
        xml_lines.append('  <domains>')
        
        domain_endpoints = defaultdict(list)
        for signature, requests in self.endpoints.items():
            domain = signature.split()[0]
            method_url_version = ' '.join(signature.split()[1:])
            domain_endpoints[domain].append((method_url_version, len(requests)))
        
        for domain in sorted(domain_endpoints.keys()):
            xml_lines.append(f'    <domain name="{domain}" endpoint_count="{len(domain_endpoints[domain])}">')
            endpoints = sorted(domain_endpoints[domain], key=lambda x: x[0])
            
            for method_url_version, count in endpoints:
                # Escape XML characters
                escaped_endpoint = method_url_version.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                xml_lines.append(f'      <endpoint count="{count}">{escaped_endpoint}</endpoint>')
            
            xml_lines.append('    </domain>')
        
        xml_lines.append('  </domains>')
        xml_lines.append('</endpoint_discovery>')
        
        return '\n'.join(xml_lines)
    
    def _format_tree(self) -> str:
        """Format discovery results in tree format (default)."""
        output_lines = []
        output_lines.append("="*80)
        output_lines.append("API ENDPOINT DISCOVERY RESULTS (Tree Format)")
        output_lines.append("="*80)
        
        # Organize endpoints by FQDN for tree format
        domain_endpoints = defaultdict(list)
        
        # Get all endpoints and organize by domain
        for signature, requests in self.endpoints.items():
            domain = signature.split()[0]  # Extract FQDN from signature
            method_url_version = ' '.join(signature.split()[1:])  # Method + URL + Version
            domain_endpoints[domain].append((method_url_version, len(requests)))
        
        # Display in tree format: FQDN -> Method URL Version
        for domain in sorted(domain_endpoints.keys()):
            output_lines.append(f"\n{domain}")
            endpoints = sorted(domain_endpoints[domain], key=lambda x: x[0])  # Sort by method+url+version
            
            for method_url_version, count in endpoints:
                output_lines.append(f"├── {method_url_version} (count: {count})")
        
        output_lines.append(f"\nSUMMARY:")
        output_lines.append(f"Total unique endpoints discovered: {len(self.endpoints)}")
        output_lines.append(f"Total requests processed: {sum(self.endpoint_counts.values())}")
        
        # Summary by domain
        output_lines.append(f"\nENDPOINT BREAKDOWN BY DOMAIN:")
        for domain in sorted(domain_endpoints.keys()):
            count = len(domain_endpoints[domain])
            output_lines.append(f"  {domain}: {count} unique endpoints")
        
        # Add statistics
        output_lines.append(self.get_statistics())
        
        return '\n'.join(output_lines)