"""
Drain Generalizer

This module contains the DrainGeneralizer class which implements 
Drain3-based template mining with enhanced masking for API endpoint generalization.
"""

import re
from urllib.parse import urlsplit, unquote
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
        from drain3.masking import MaskingInstruction
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
        template_config.drain_extra_delimiters = config.get('extra_delimiters', ["?", "&", "="])
        
        # Configure masking prefix/suffix
        template_config.mask_prefix = config.get('mask_prefix', '{')
        template_config.mask_suffix = config.get('mask_suffix', '}')
        
        # Configure masking instructions using Drain3's built-in masking
        # Order matters: more specific patterns should come first
        template_config.masking_instructions = [
            # UTF-8 encoded Chinese characters
            MaskingInstruction(r"[\u4e00-\u9fff]+", "Chinese Characters"),

            # Email addresses
            MaskingInstruction(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "EMAIL"),

            # Dates in YYYY-MM-DD or similar formats
            MaskingInstruction(r"\b[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])[ T](?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):?[0-5][0-9])?\b", "DATE_TIME"),

            # MAC addresses
            MaskingInstruction(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b", "MAC"),

            # URI scheme (http, https, ftp, file, rmi)
            MaskingInstruction(r"\b(?:[a-zA-Z]{3,}):\/\/[a-zA-Z0-9.-]{2,}", "URI_SCHEME"),

            # JWT tokens (Base64 with dots)
            MaskingInstruction(r"eyJ[A-Za-z0-9+\/=]+\.[A-Za-z0-9+\/=]+\.[A-Za-z0-9+\/=]+", "JWT"),
            
            # UUIDs with dashes (must come before general hex patterns)
            MaskingInstruction(r"\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b", "UUID"),
            
            # Hex values with 0x prefix
            MaskingInstruction(r"\b0x[a-fA-F0-9]+\b", "HEX"),
            
            # IPv4 addresses - use word boundaries and negative lookahead to avoid matching version numbers like 1.7.8.0123
            # The pattern requires the IP to be followed by a word boundary (not another digit)
            MaskingInstruction(r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b(?!\d)", "IPv4"),

            # IPV6 addresses
            
            # Chinese IDentification Numbers
            MaskingInstruction(r"\b\d{6}(19|20)?\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}([0-9Xx])\b", "CHN_ID."),

            # Credit Card Numbers (Visa, MasterCard, Amex, Discover)
            MaskingInstruction(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", "CREDIT_Card_No."),

            # Chinese Band Card Numbers
            MaskingInstruction(r"\b(62|43|40|52|51|58)\d{14,17}\b", "CHN_BankCardNo."),

            # Chinese Phone Numbers
            MaskingInstruction(r"\b1[3456789]\d{9}\b", "CHN_Phone_No."),

            # Base64 encoded data (long Base64 strings)
            MaskingInstruction(r"\b[A-Za-z0-9+\/]{16,}={0,2}\b", "BASE64"),

            # # URL-Safe Base64 encoded data
            MaskingInstruction(r"\b[A-Za-z0-9\-_]{16,}={0,2}\b", "BASE64URL"),

            # Dot separated numbers (e.g., version numbers)
            MaskingInstruction(r"\b\d+(\.\d+){2,}\b", "DOT_SEP_Num"),

            # Numbers (integers) - comes after IP addresses
            MaskingInstruction(r"^\d+\b", "NUM"),

            # Date in YYYYMMDD format
            MaskingInstruction(r"\b20\d{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])\b", "DATE_DIGITS"),

            # DateTime in YYYYMMDDHHMMSS format
            MaskingInstruction(r"\b20\d{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])(0[0-9]|1[0-9]|2[0-3])[0-5][0-9][0-5][0-9]\b", "DATETIME_DIGITS"),

            # Long hex strings (8+ chars, but not caught by UUID)
            MaskingInstruction(r"\b[a-fA-F0-9]{8,}\b", "HEX"),
        ]
        
        # Snapshot settings (disabled for runtime use)
        template_config.snapshot_interval_minutes = 0
        template_config.snapshot_compress_state = False
        
        return TemplateMiner(config=template_config)
    
    def process_http_message(self, host: str, scheme: str, method: str, url: str, http_version: str) -> str:
        """Process a single HTTP message and return the generalized endpoint signature."""
        if method.upper() == 'CONNECT':
            # For CONNECT requests, the URL is the authority (host:port)
            # urlsplit misinterprets "host:port" as "scheme:path" (e.g. "host" as scheme, "port" as path)
            generalized_path = self.generalize_path(url)
            generalized_query = ""
        else:
            u = urlsplit(url)
            
            # Generalize path and parameters separately
            generalized_path = self.generalize_path(u.path)
            generalized_query = self.generalize_query_params(u.query)
        
        # Create the endpoint signature - format: <FQDN> <Method> <URL Path with parameters>
        # Note: HTTP version is ignored for generalization as requested
        full_path = generalized_path + generalized_query
        signature = f"{host} {method.upper()} {full_path}"
        
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
        """Generalize query parameters using Drain3 templates.
        
        Only parameter values are masked/generalized, keys are preserved.
        """
        if not query_string:
            return ""
        
        if self.use_drain3:
            generalized = self._drain3_generalize_query(query_string)
            return "?" + generalized
        
        return "?" + query_string
    
    def _drain3_generalize_query(self, query_string: str) -> str:
        """Use Drain3 to generalize query parameter values only.
        
        Preserves parameter keys and only applies masking/generalization to values.
        """
        if not self.use_drain3 or not self.drain3_miner:
            return query_string
        
        try:
            # Parse query string into key=value pairs
            params = query_string.split('&')
            generalized_params = []
            
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)

                    if key.endswith('token'):
                        generalized_params.append(f"{key}=<TOKEN>")
                        continue
                    
                    # Only process the value through Drain3
                    if value:
                        # URL decode the value before masking
                        decoded_value = unquote(value)

                        # decode as urlencoded recursively if needed
                        seglist = []
                        for segment in decoded_value.split(' '):
                            percent_count = len(re.findall(r'%[0-9A-Fa-f]{2}', segment))
                            if len(segment) > 0:
                                if percent_count / len(segment) > 0.1:
                                    seglist.append(unquote(segment))
                                else:
                                    seglist.append(segment)
                            else:
                                seglist.append(segment)
                        decoded_value = ' '.join(seglist)

                        result = self.drain3_miner.add_log_message(decoded_value)
                        if result and isinstance(result, dict) and 'template_mined' in result:
                            generalized_value = result['template_mined']
                            
                            # Fix broken placeholders caused by Drain3 adding {*} inside masked values
                            # e.g., "{Chinese {*}" -> "{Chinese Characters}"
                            generalized_value = self._fix_broken_placeholders(generalized_value)
                            
                            # Track if generalization happened
                            if generalized_value != decoded_value and ('{' in generalized_value or '<' in generalized_value):
                                self.pattern_stats['Drain3 Templates'] += 1
                            
                            generalized_params.append(f"{key}={generalized_value}")
                        else:
                            generalized_params.append(param)
                    else:
                        # Empty value, keep as is
                        generalized_params.append(param)
                else:
                    # No '=' in param (malformed or flag-style), keep as is
                    generalized_params.append(param)
            
            return '&'.join(generalized_params)
            
        except Exception as e:
            # If Drain3 fails, return original query string
            return query_string
    
    def _fix_broken_placeholders(self, text: str) -> str:
        """Fix placeholders that were broken by Drain3's {*} wildcard insertion.
        
        When Drain3 creates templates, it may insert {*} wildcards inside already-masked
        placeholders, creating broken patterns like "{Chinese {*}" instead of "{Chinese Characters}".
        This method detects and fixes these broken placeholders.
        """
        # Known placeholder names that may get broken
        placeholder_names = [
            "Chinese Characters",
            "EMAIL",
            "URI_SCHEME", 
            "JWT",
            "UUID",
            "BASE64",
            "BASE64URL",
            "HEX",
            "IPv4",
            "CHN_ID_Card",
            "CHN_Phone_No.",
            "CHN_Bank_Card",
            "INT",
        ]
        
        # Fix patterns like "{Chinese {*}" or "{Chinese {*} Characters}" -> "{Chinese Characters}"
        for name in placeholder_names:
            words = name.split()
            if len(words) > 1:
                # Multi-word placeholder like "Chinese Characters"
                first_word = words[0]
                last_word = words[-1]
                
                # Pattern 1: "{FirstWord {*}" or "{FirstWord {*} anything}" -> "{Chinese Characters}"
                # Match from opening brace through any wildcards/text until we hit end or another opening brace
                broken_pattern = re.compile(
                    r'\{' + re.escape(first_word) + r'\s+\{\*\}[^{}]*',
                    re.IGNORECASE
                )
                text = broken_pattern.sub('{' + name + '}', text)
                
                # Pattern 2: "{*} LastWord}" -> "{Chinese Characters}"
                broken_end_pattern = re.compile(
                    r'\{\*\}\s*' + re.escape(last_word) + r'\}',
                    re.IGNORECASE
                )
                text = broken_end_pattern.sub('{' + name + '}', text)
            
            # Fix cases where the placeholder itself became a wildcard
            # e.g., when "{Chinese Characters}" becomes "{Chinese Characters} {*}"
            text = re.sub(
                r'\{' + re.escape(name) + r'\}\s*\{\*\}',
                '{' + name + '}',
                text
            )
        
        return text
    
    def _drain3_generalize_path(self, path: str) -> str:
        """Use Drain3 to generalize URL path segments."""
        if not self.use_drain3 or not self.drain3_miner:
            return path
            
        try:
            if path.startswith('/'):
                # URL path - convert /a/b/c to "a b c" for Drain3 processing
                segments = [seg for seg in path.strip('/').split('/') if seg]
                
                # Check if last segment looks like a file with extension
                suffix_segment = None
                if segments and re.search(r'\.[a-zA-Z0-9]+$', segments[-1]):
                    suffix_segment = segments[-1]
                    segments = segments[:-1]
                
                segments_str = ' '.join(segments) if segments else 'root'
                
                # Process through Drain3 (masking is handled by Drain3's MaskingInstructions)
                result = self.drain3_miner.add_log_message(segments_str)
                if result and isinstance(result, dict) and 'template_mined' in result:
                    template = result['template_mined']
                    
                    # Fix broken placeholders caused by Drain3 adding {*} inside masked values
                    template = self._fix_broken_placeholders(template)
                    
                    # Reconstruct URL path
                    template_segments = template.split()
                    generalized_path = '/' + '/'.join(template_segments) if template_segments != ['root'] else '/'
                    
                    # Append the suffix segment if it existed
                    if suffix_segment:
                        if generalized_path == '/':
                            generalized_path = '/' + suffix_segment
                        else:
                            generalized_path = generalized_path + '/' + suffix_segment
                    
                    # Only count as a template if it actually generalized something
                    if template != segments_str and ('{' in template or '<' in template):
                        self.pattern_stats['Drain3 Templates'] += 1
                    else:
                        self.pattern_stats['No Pattern'] += 1
                        
                    return generalized_path
            else:
                # Non-URL path, process directly
                result = self.drain3_miner.add_log_message(path)
                if result and isinstance(result, dict) and 'template_mined' in result:
                    template = result['template_mined']
                    
                    # Fix broken placeholders
                    template = self._fix_broken_placeholders(template)
                    
                    if template != path and ('{' in template or '<' in template):
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
            # Signature format: <FQDN> <Method> <URL Path with parameters>
            parts = signature.split(' ', 2)
            if len(parts) >= 3:
                domain, method, path = parts[0], parts[1], parts[2]
                
                # Create a pattern key by replacing specific values with wildcards
                pattern_key = self._create_pattern_key(domain, method, path)
                
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
    
    def _create_pattern_key(self, domain: str, method: str, path: str) -> str:
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
        
        return f"{domain} {method} {full_pattern}"