"""
Drain Generalizer

This module contains the DrainGeneralizer class which implements 
Drain3-based template mining with enhanced masking for API endpoint generalization.
"""

import re
from urllib.parse import urlsplit
from .base import Generalizer


class DrainGeneralizer(Generalizer):
    """Drain3-based template generalization system."""
    
    def __init__(self, drain3_config=None):
        """Initialize the Drain3 generalization system."""
        super().__init__()
        self.pattern_cache = {}  # Cache for analyzed patterns
        
        # Pattern source tracking
        self.pattern_stats = {
            'Drain3 Templates': 0,
            'No Pattern': 0
        }
        
        # Initialize Drain3 template miner with runtime configuration
        try:
            self.drain3_miner = self._create_drain3_miner(drain3_config)
            self.use_drain3 = True
            print("DrainGeneralizer initialized - Mode: Drain3 Template Mining")
        except Exception as e:
            print(f"Warning: Failed to initialize Drain3: {e}")
            self.drain3_miner = None
            self.use_drain3 = False
    
    def _create_drain3_miner(self, config=None):
        """Create Drain3 TemplateMiner with runtime configuration."""
        from drain3.template_miner_config import TemplateMinerConfig
        from drain3 import TemplateMiner
        
        # Create configuration programmatically
        template_config = TemplateMinerConfig()
        
        # Set default values or use provided config
        if config is None:
            config = {}
        
        # Drain3 algorithm parameters
        template_config.drain_sim_th = config.get('similarity_threshold', 0.3)
        template_config.drain_depth = config.get('depth', 5)
        template_config.drain_max_children = config.get('max_children', 100)
        template_config.drain_max_clusters = config.get('max_clusters', 1024)
        # For URL paths, we don't want '/' as a delimiter since it's structural
        # Instead, we'll use delimiters that separate parameter values
        template_config.drain_extra_delimiters = config.get('extra_delimiters', ["_", "?", "&", "=", "-"])
        
        # Store masking patterns for manual pre-processing (Drain3 built-in masking doesn't work reliably)
        self.masking_patterns = config.get('masking_patterns', [
            # JWT tokens (Base64 with dots) - Order matters: more specific patterns first
            {"regex_pattern": r"eyJ[A-Za-z0-9+\/=]+\.[A-Za-z0-9+\/=]+\.[A-Za-z0-9+\/=]+", "mask_with": "JWT"},
            
            # UUIDs with dashes (must come before general hex patterns)
            {"regex_pattern": r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}", "mask_with": "UUID"},
            
            # Base64 encoded data (long Base64 strings) 
            {"regex_pattern": r"[A-Za-z0-9+\/]{20,}={0,2}", "mask_with": "BASE64"},
            
            # UUIDs without dashes (32 hex chars - must come before general hex)
            {"regex_pattern": r"\b[a-fA-F0-9]{32}\b", "mask_with": "UUID"},
            
            # Hex values with 0x prefix
            {"regex_pattern": r"0x[a-fA-F0-9]+", "mask_with": "HEX"},
            
            # IP addresses (must come before general numbers)
            {"regex_pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "mask_with": "IP"},
            
            # Long hex strings (8+ chars, but not caught by UUID)
            {"regex_pattern": r"\b[a-fA-F0-9]{8,}\b", "mask_with": "HEX"},
            
            # Numbers (integers) - comes after IP addresses
            {"regex_pattern": r"\b\d+\b", "mask_with": "INT"},
            
            # Alphanumeric tokens (6+ chars) - least specific
            {"regex_pattern": r"\b[a-zA-Z0-9]{6,}\b", "mask_with": "TOKEN"},
        ])
        
        template_config.mask_prefix = config.get('mask_prefix', '{')
        template_config.mask_suffix = config.get('mask_suffix', '}')
        
        # Snapshot settings (disabled for runtime use)
        template_config.snapshot_interval_minutes = 0
        template_config.snapshot_compress_state = False
        
        return TemplateMiner(config=template_config)
    
    def _apply_masking_patterns(self, message: str) -> str:
        """Apply masking patterns manually before feeding to Drain3."""
        if not hasattr(self, 'masking_patterns') or not self.masking_patterns:
            return message
        
        masked = message
        for pattern_config in self.masking_patterns:
            pattern = pattern_config['regex_pattern']
            replacement = f"{{{pattern_config['mask_with']}}}"
            old_masked = masked
            masked = re.sub(pattern, replacement, masked)
            
            # Track successful masking for statistics
            if masked != old_masked:
                self.pattern_stats['Drain3 Templates'] += 1
                break  # Only apply first matching pattern per token
        
        return masked
    
    def process_http_message(self, host: str, scheme: str, method: str, url: str, http_version: str) -> str:
        """Process a single HTTP message and return the generalized endpoint signature."""
        u = urlsplit(url)
        
        # Generalize path and parameters separately
        generalized_path = self.generalize_path(u.path)
        generalized_query = self.generalize_query_params(u.query)
        
        # Create the endpoint signature - format: <FQDN> <Method> <URL Path with parameters> <HTTP Version>
        full_path = generalized_path + generalized_query
        signature = f"{host} {method.upper()} {full_path} {http_version}"
        
        return signature
    
    def generalize_path(self, path: str) -> str:
        """Generalize URL path using Drain3 templates."""
        if not path or path == '/':
            return '/'
        
        # Try Drain3 on the complete path first
        if self.use_drain3:
            drain3_result = self._drain3_generalize_path(path)
            if drain3_result != path:
                return drain3_result
        
        # If Drain3 didn't find a pattern, return original path
        self.pattern_stats['No Pattern'] += 1
        return path
    
    def generalize_query_params(self, query_string: str) -> str:
        """Generalize query parameters using Drain3 templates."""
        if not query_string:
            return ""
        
        full_query = "?" + query_string
        
        # Try Drain3 on the complete query string
        if self.use_drain3:
            drain3_result = self._drain3_generalize_path(full_query)
            if drain3_result != full_query:
                return drain3_result
        
        # If Drain3 didn't find a pattern, return original query
        self.pattern_stats['No Pattern'] += 1
        return full_query
    
    def _drain3_generalize_path(self, path: str) -> str:
        """Use Drain3 to generalize complete URL paths and parameters."""
        if not self.use_drain3 or not self.drain3_miner:
            return path
            
        try:
            # For URL paths, we need to preserve the structure while allowing Drain3 to generalize
            # Convert path segments to space-separated format for Drain3, then convert back
            if path.startswith('/') or path.startswith('?'):
                # Split path into segments but preserve structure info
                if path.startswith('?'):
                    # Query string - convert to format suitable for Drain3
                    query_without_q = path[1:]  # Remove ? prefix
                    # Replace query parameter delimiters with spaces for Drain3 processing
                    segments_str = query_without_q.replace('&', ' ').replace('=', ' ')
                else:
                    # URL path - convert /a/b/c to "a b c" for Drain3 processing
                    segments = [seg for seg in path.strip('/').split('/') if seg]
                    segments_str = ' '.join(segments) if segments else 'root'
                
                # Apply manual masking first before feeding to Drain3
                masked_segments = self._apply_masking_patterns(segments_str)
                
                # Process masked segments through Drain3
                result = self.drain3_miner.add_log_message(masked_segments)
                if result and isinstance(result, dict) and 'template_mined' in result:
                    template = result['template_mined']
                    # Always use the template if one was found, even if it's the same as input
                    # This ensures consistent generalization
                    if path.startswith('?'):
                        # Reconstruct query string with proper formatting
                        # Convert space-separated template back to query format
                        template_parts = template.split()
                        # Group pairs back into key=value format
                        query_parts = []
                        for i in range(0, len(template_parts), 2):
                            if i + 1 < len(template_parts):
                                key = template_parts[i]
                                value = template_parts[i + 1]
                                query_parts.append(f"{key}={value}")
                            else:
                                query_parts.append(template_parts[i])
                        generalized_path = '?' + '&'.join(query_parts)
                    else:
                        # Reconstruct URL path
                        template_segments = template.split()
                        generalized_path = '/' + '/'.join(template_segments) if template_segments != ['root'] else '/'
                    
                    # Only count as a template if it actually generalized something
                    if template != segments_str and '{' in template and '}' in template:
                        self.pattern_stats['Drain3 Templates'] += 1
                    else:
                        self.pattern_stats['No Pattern'] += 1
                        
                    return generalized_path
            else:
                # Non-URL path, process directly
                result = self.drain3_miner.add_log_message(path)
                if result and isinstance(result, dict) and 'template_mined' in result:
                    template = result['template_mined']
                    if template != path and '{' in template and '}' in template:
                        self.pattern_stats['Drain3 Templates'] += 1
                        return template
                        
        except Exception as e:
            # If Drain3 fails, fall back to original path
            pass
            
        return path
    
    def _post_process_drain3_patterns(self):
        """Post-process endpoints to merge patterns that should be generalized together."""
        # Group endpoints by their structural similarity
        pattern_groups = {}
        signatures_to_remove = []
        
        for signature, requests in list(self.endpoints.items()):
            # Extract the path part of the signature for pattern matching
            parts = signature.split(' ', 3)
            if len(parts) >= 3:
                domain, method, path_and_version = parts[0], parts[1], ' '.join(parts[2:])
                
                # Split path from HTTP version
                path_parts = path_and_version.rsplit(' ', 1)
                if len(path_parts) == 2:
                    path, version = path_parts
                    
                    # Create a pattern key by replacing specific values with wildcards
                    pattern_key = self._create_pattern_key(domain, method, path, version)
                    
                    if pattern_key not in pattern_groups:
                        pattern_groups[pattern_key] = {
                            'signatures': [],
                            'requests': [],
                            'generalized_signature': None
                        }
                    
                    pattern_groups[pattern_key]['signatures'].append(signature)
                    pattern_groups[pattern_key]['requests'].extend(requests)
        
        # Merge patterns that have multiple signatures
        for pattern_key, group in pattern_groups.items():
            if len(group['signatures']) > 1:
                # Find the most generalized signature (the one with {*} wildcards)
                generalized_sig = None
                specific_sigs = []
                
                for sig in group['signatures']:
                    if '{*}' in sig:
                        generalized_sig = sig
                    else:
                        specific_sigs.append(sig)
                
                # If we have both specific and generalized signatures, merge them
                if generalized_sig and specific_sigs:
                    # Merge all requests into the generalized signature
                    all_requests = []
                    total_count = 0
                    
                    for sig in group['signatures']:
                        all_requests.extend(self.endpoints[sig])
                        total_count += self.endpoint_counts[sig]
                        if sig != generalized_sig:
                            signatures_to_remove.append(sig)
                    
                    # Update the generalized signature with all requests
                    self.endpoints[generalized_sig] = all_requests
                    self.endpoint_counts[generalized_sig] = total_count
        
        # Remove the specific signatures that were merged
        for sig in signatures_to_remove:
            if sig in self.endpoints:
                del self.endpoints[sig]
            if sig in self.endpoint_counts:
                del self.endpoint_counts[sig]
    
    def _create_pattern_key(self, domain: str, method: str, path: str, version: str) -> str:
        """Create a pattern key for grouping similar endpoints."""
        # Replace numbers, specific IDs, and Drain3 wildcards with a normalized placeholder
        
        # Handle both URL paths and query parameters
        if '?' in path:
            # Split path and query string
            path_part, query_part = path.split('?', 1)
            
            # Normalize path part
            path_pattern = re.sub(r'/\d+', '/{*}', path_part)
            path_pattern = re.sub(r'/[0-9a-fA-F]{8,}', '/{*}', path_pattern)
            path_pattern = re.sub(r'/[a-zA-Z0-9_-]{6,}', '/{*}', path_pattern)
            path_pattern = re.sub(r'/\{\*\}', '/{*}', path_pattern)
            
            # Normalize query parameters - replace values but keep structure
            query_pattern = re.sub(r'=[^&]+', '={*}', query_part)  # Replace param values
            query_pattern = re.sub(r'=\{\*\}', '={*}', query_pattern)  # Normalize existing {*}
            
            full_pattern = path_pattern + '?' + query_pattern
        else:
            # Just a path, no query parameters
            full_pattern = re.sub(r'/\d+', '/{*}', path)
            full_pattern = re.sub(r'/[0-9a-fA-F]{8,}', '/{*}', full_pattern)
            full_pattern = re.sub(r'/[a-zA-Z0-9_-]{6,}', '/{*}', full_pattern)
            full_pattern = re.sub(r'/\{\*\}', '/{*}', full_pattern)
        
        return f"{domain} {method} {full_pattern} {version}"