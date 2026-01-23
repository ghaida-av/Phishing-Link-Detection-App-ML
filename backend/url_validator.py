
import re
from urllib.parse import urlparse


class URLValidator:
  
    
  
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    

    URL_PATTERN = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|' 
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    
   
    URLPATTERN = re.compile(
        r'^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?(?:/?|[/?]\S+)?$', re.IGNORECASE
    )
    
    @staticmethod
    def is_email(text: str) -> bool:
       
        if not text:
            return False
        
        text = text.strip()
        return bool(URLValidator.EMAIL_PATTERN.match(text))
    
    @staticmethod
    def is_url(text: str) -> bool:
        
        if not text:
            return False
        
        text = text.strip()
        
     
        if URLValidator.is_email(text):
            return False
        
       
        if URLValidator.URL_PATTERN.match(text):
            return True
       
        if URLValidator.URLPATTERN .match(text):
            return True
        
      
        if text.lower().startswith('www.'):
            return True
        
        
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co', 
                      '.uk', '.de', '.fr', '.jp', '.cn', '.au', '.ca']
        if any(text.lower().endswith(tld) or f'.{tld}' in text.lower() 
               for tld in common_tlds):
         
            if '@' not in text:
                return True
        
        
        try:
            
            test_url = text if '://' in text else 'http://' + text
            parsed = urlparse(test_url)
            
           
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
        
       
        if URLValidator.is_email(url):
            return url
        
        
        if '://' in url:
            return url
        
       
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
        
        if URLValidator.is_email(text):
            return {
                'is_valid': True,
                'type': 'email',
                'normalized': text.lower()
            }
      
        if URLValidator.is_url(text):
            normalized = URLValidator.normalize_url(text)
            return {
                'is_valid': True,
                'type': 'url',
                'normalized': normalized.lower()
            }
     
        return {
            'is_valid': False,
            'type': 'invalid',
            'normalized': text
        }
