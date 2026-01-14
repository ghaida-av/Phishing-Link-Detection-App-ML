"""
URL and Email Validator
Differentiates between URLs and emails, validates them
"""
import re
from urllib.parse import urlparse


class URLValidator:
    """Validates URLs and emails, differentiates between them"""
    
    # Email regex pattern
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    # URL regex pattern (more comprehensive)
    URL_PATTERN = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    
    # Simplified URL pattern (for URLs without protocol)
    URL_PATTERN_SIMPLE = re.compile(
        r'^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?(?:/?|[/?]\S+)?$', re.IGNORECASE
    )
    
    @staticmethod
    def is_email(text: str) -> bool:
        """Check if input is an email address"""
        if not text:
            return False
        
        text = text.strip()
        return bool(URLValidator.EMAIL_PATTERN.match(text))
    
    @staticmethod
    def is_url(text: str) -> bool:
        """Check if input is a URL"""
        if not text:
            return False
        
        text = text.strip()
        
        # Check if it's an email first (emails can contain URLs in some contexts)
        if URLValidator.is_email(text):
            return False
        
        # Check full URL pattern (with protocol)
        if URLValidator.URL_PATTERN.match(text):
            return True
        
        # Check simple URL pattern (without protocol)
        if URLValidator.URL_PATTERN_SIMPLE.match(text):
            return True
        
        # Additional check: if it starts with www. or contains common TLDs
        if text.lower().startswith('www.'):
            return True
        
        # Check for common TLDs
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co', 
                      '.uk', '.de', '.fr', '.jp', '.cn', '.au', '.ca']
        if any(text.lower().endswith(tld) or f'.{tld}' in text.lower() 
               for tld in common_tlds):
            # Make sure it's not just a domain name that's part of an email
            if '@' not in text:
                return True
        
        # Try parsing as URL
        try:
            # Add protocol if missing
            test_url = text if '://' in text else 'http://' + text
            parsed = urlparse(test_url)
            
            # Must have at least a netloc (domain) or a valid path
            if parsed.netloc or (parsed.path and '.' in parsed.path):
                return True
        except:
            pass
        
        return False
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL by adding protocol if missing"""
        url = url.strip()
        
        if not url:
            return url
        
        # If it's an email, return as is
        if URLValidator.is_email(url):
            return url
        
        # If it already has a protocol, return as is
        if '://' in url:
            return url
        
        # Add http:// if it looks like a URL
        if URLValidator.is_url(url):
            return 'http://' + url
        
        return url
    
    @staticmethod
    def validate_and_classify(text: str) -> dict:
        """
        Validate input and classify as URL or email
        Returns: {
            'is_valid': bool,
            'type': 'url' | 'email' | 'invalid',
            'normalized': str
        }
        """
        if not text or not text.strip():
            return {
                'is_valid': False,
                'type': 'invalid',
                'normalized': text
            }
        
        text = text.strip()
        
        # Check if it's an email
        if URLValidator.is_email(text):
            return {
                'is_valid': True,
                'type': 'email',
                'normalized': text.lower()
            }
        
        # Check if it's a URL
        if URLValidator.is_url(text):
            normalized = URLValidator.normalize_url(text)
            return {
                'is_valid': True,
                'type': 'url',
                'normalized': normalized.lower()
            }
        
        # Invalid input
        return {
            'is_valid': False,
            'type': 'invalid',
            'normalized': text
        }
