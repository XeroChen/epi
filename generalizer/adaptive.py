"""
Adaptive Generalizer

This module contains the AdaptiveGeneralizer class which implements 
adaptive pattern detection and semantic generalization for API endpoints.
"""

import math
import re
from collections import defaultdict, Counter
from urllib.parse import urlsplit, parse_qsl, unquote
from .base import Generalizer

# Pre-masking regexes for variable tokens
MASKS = [
    (re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', re.I), r'{UUID}'),
    (re.compile(r'0x[a-fA-F0-9]+', re.I), r'{HEX}'),
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), r'{IP}'),
    (re.compile(r'\b\d{10}(\d{3})?\b'), r'{EPOCH}'),
    (re.compile(r'\b\d{4}-\d{2}-\d{2}\b'), r'{DATE}'),
    (re.compile(r'\b[0-9a-f]{8,}\b', re.I), r'{HEX}'),
    (re.compile(r'\b\d+\b'), r'{INT}'),
    (re.compile(r'\b[A-Za-z0-9]{6,}\b'), r'{TOKEN}'),  # 6-character alphanumeric tokens
    (re.compile(r'[A-Za-z0-9_-]{20,}'), r'{*}'),
]


class AdaptiveGeneralizer(Generalizer):
    """Adaptive pattern detection and generalization system for URLs and parameters."""
    
    def __init__(self):
        """Initialize the adaptive generalization system."""
        super().__init__()
        self.pattern_cache = {}  # Cache for analyzed patterns
        self.value_frequencies = defaultdict(Counter)  # Track value frequencies by position
        self.learned_patterns = []  # Dynamically learned patterns
        self.min_entropy_threshold = 2.0  # Minimum entropy for considering generalization
        self.min_length_for_analysis = 3  # Minimum length to analyze
        
        # Pattern source tracking
        self.pattern_stats = {
            'JWT Detection': 0,
            'Base64 Detection': 0,
            'Regex Masks': 0,
            'Custom Patterns': 0,
            'No Pattern': 0
        }
        
        print("AdaptiveGeneralizer initialized - Mode: Adaptive Pattern Detection")
    
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
        """Generalize URL path by replacing variables in each directory level."""
        if not path or path == '/':
            return '/'
        
        # Split path into segments, preserving leading slash
        segments = path.strip('/').split('/')
        generalized_segments = []
        
        for i, segment in enumerate(segments):
            if segment:  # Skip empty segments
                normalized_segment = self._normalize_url_component(segment)
                should_mask, pattern = self.should_generalize(normalized_segment, f"path:{i}")
                generalized_segments.append(pattern if should_mask else normalized_segment)
        
        return '/' + '/'.join(generalized_segments)
    
    def generalize_query_params(self, query_string: str) -> str:
        """Generalize query parameter values while preserving parameter names."""
        if not query_string:
            return ""
        
        params = parse_qsl(query_string, keep_blank_values=True)
        generalized_params = []
        
        for key, value in params:
            # Generalize the value but keep the key
            if value:
                normalized_value = self._normalize_url_component(value)
                should_mask, pattern = self.should_generalize(normalized_value, f"param:{key}")
                generalized_value = pattern if should_mask else normalized_value
            else:
                generalized_value = value
            generalized_params.append(f"{key}={generalized_value}")
        
        # Sort parameters for consistency
        generalized_params.sort()
        return "?" + "&".join(generalized_params)
        
    def calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if len(s) < 2:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(s.lower())
        length = len(s)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_character_composition(self, s: str) -> dict:
        """Analyze the character composition of a string."""
        total_chars = len(s)
        if total_chars == 0:
            return {'letters': 0, 'digits': 0, 'special': 0, 'mixed': False}
        
        letters = sum(1 for c in s if c.isalpha())
        digits = sum(1 for c in s if c.isdigit())
        special = sum(1 for c in s if not c.isalnum())
        
        return {
            'letters': letters / total_chars,
            'digits': digits / total_chars,
            'special': special / total_chars,
            'mixed': (letters > 0 and digits > 0),
            'length': total_chars
        }
    
    def detect_pattern_type(self, s: str) -> str:
        """Detect what type of pattern a string represents."""
        if len(s) < self.min_length_for_analysis:
            return None
        
        # Check for JWT tokens (header.payload.signature format)
        if self._is_jwt(s):
            return '<JWT>'
        
        # Check for Base64-encoded content
        base64_type = self._detect_base64_type(s)
        if base64_type:
            return base64_type
            
        composition = self.analyze_character_composition(s)
        entropy = self.calculate_entropy(s)
        length = len(s)
        
        # High entropy suggests randomness (likely an ID/token)
        if entropy >= self.min_entropy_threshold:
            if composition['mixed']:
                if 6 <= length <= 12:
                    return '<TOKEN>'
                elif 13 <= length <= 20:
                    return '<ID>'
                elif length > 20:
                    return '<HASH>'
            elif composition['digits'] > 0.8:
                if length >= 10:
                    return '<BIGINT>'
                else:
                    return '<NUM>'
            elif composition['letters'] > 0.8:
                if length >= 8:
                    return '<CODE>'
        
        # Pattern-based detection for lower entropy but structured data
        if composition['digits'] == 1.0 and length >= 4:
            return '<ID_NUM>'
        
        if composition['letters'] > 0.6 and composition['digits'] > 0.2 and length >= 6:
            return '<ALPHANUM>'
            
        return None
    
    def _is_jwt(self, s: str) -> bool:
        """Check if string is a JWT token (3 base64 parts separated by dots)."""
        # JWT pattern: base64.base64.base64
        jwt_pattern = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
        if jwt_pattern.match(s):
            parts = s.split('.')
            return len(parts) == 3 and all(len(part) > 0 for part in parts)
        return False
    
    def _detect_base64_type(self, s: str) -> str:
        """Detect if string is base64-encoded and determine content type."""
        import base64
        
        # Check if it looks like base64 (alphanumeric + / + = padding)
        base64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
        if not base64_pattern.match(s) or len(s) < 8:
            return None
        
        # Try to decode as base64
        try:
            # Handle URL-safe base64 variants
            s_normalized = s.replace('-', '+').replace('_', '/')
            # Add padding if needed
            while len(s_normalized) % 4:
                s_normalized += '='
            
            decoded = base64.b64decode(s_normalized).decode('utf-8')
            
            # Check if decoded content is JSON
            if self._is_json(decoded):
                return '<BASE64-JSON>'
            
            # Check if decoded content is XML
            if self._is_xml(decoded):
                return '<BASE64-XML>'
            
            # Check if decoded content is a JWT
            if self._is_jwt(decoded):
                return '<BASE64-JWT>'
                
        except (Exception, UnicodeDecodeError):
            # If decoding fails, it might still be base64 but binary content
            pass
        
        return None
    
    def _is_json(self, s: str) -> bool:
        """Check if string is valid JSON."""
        try:
            import json
            json.loads(s.strip())
            return True
        except (json.JSONDecodeError, ValueError):
            return False
    
    def _is_xml(self, s: str) -> bool:
        """Check if string is valid XML."""
        s_stripped = s.strip()
        # Simple XML detection - starts with < and has closing tags
        xml_pattern = re.compile(r'^\s*<[^>]+>.*</[^>]+>\s*$', re.DOTALL)
        return xml_pattern.match(s_stripped) is not None
    
    def _normalize_url_component(self, s: str) -> str:
        """Normalize URL component by decoding URL encoding."""
        try:
            # Apply URL decoding
            decoded = unquote(s)
            return decoded
        except Exception:
            # If decoding fails, return original string
            return s

    def should_generalize(self, s: str, context: str = "") -> tuple:
        """Determine if a string should be generalized and return the pattern."""
        # First check cache
        cache_key = f"{s}:{context}"
        if cache_key in self.pattern_cache:
            return self.pattern_cache[cache_key]
        
        # PHASE 1: Check for specific high-priority patterns (JWT, Base64 types)
        if self._is_jwt(s):
            self.pattern_stats['JWT Detection'] += 1
            result = (True, '<JWT>')
            self.pattern_cache[cache_key] = result
            return result
        
        base64_type = self._detect_base64_type(s)
        if base64_type:
            self.pattern_stats['Base64 Detection'] += 1
            result = (True, base64_type)
            self.pattern_cache[cache_key] = result
            return result
        
        # PHASE 2: Apply predefined MASKS (these have priority over generic adaptive patterns)
        for pattern, replacement in MASKS:
            if pattern.match(s):
                self.pattern_stats['Regex Masks'] += 1
                result = (True, replacement)
                self.pattern_cache[cache_key] = result
                return result
        
        # PHASE 3: Apply remaining adaptive detection for patterns not covered by MASKS
        detected_pattern = self.detect_pattern_type(s)
        if detected_pattern and detected_pattern not in ['<JWT>', '<BASE64-JSON>', '<BASE64-XML>', '<BASE64-JWT>']:
            self.pattern_stats['Custom Patterns'] += 1
            result = (True, detected_pattern)
            self.pattern_cache[cache_key] = result
            return result
        
        # No generalization needed
        self.pattern_stats['No Pattern'] += 1
        result = (False, s)
        self.pattern_cache[cache_key] = result
        return result