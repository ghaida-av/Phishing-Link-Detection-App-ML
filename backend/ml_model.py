"""
ML Model for Phishing URL Detection
Uses feature extraction and a trained classifier
"""
import re
import pickle
import os
from urllib.parse import urlparse
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import warnings
warnings.filterwarnings('ignore')


class PhishingURLDetector:
    def __init__(self):
        self.model = None
        self.model_path = 'phishing_model.pkl'
        self.load_or_train_model()

    # ----------------------------
    # Beginner-friendly helpers
    # ----------------------------
    @staticmethod
    def _normalize_url(url: str) -> str:
        """Add a protocol if missing (so urlparse works consistently)."""
        return url if '://' in url else 'http://' + url

    @staticmethod
    def _safe_urlparse(url: str):
        """Parse URL safely. Returns None if parsing fails."""
        try:
            return urlparse(PhishingURLDetector._normalize_url(url))
        except Exception:
            return None
    
    def extract_features(self, url):
        """
        Extract features from URL for ML model
        Returns a feature vector
        """
        features = []
        url_lower = url.lower()

        # -------- 1) Basic URL features (9) --------
        features.append(len(url))           # URL length
        features.append(url.count('.'))     # dots
        features.append(url.count('-'))     # hyphens
        features.append(url.count('_'))     # underscores
        features.append(url.count('/'))     # slashes
        features.append(url.count('?'))     # question marks
        features.append(url.count('='))     # equals signs
        features.append(url.count('@'))     # @ symbols
        features.append(url.count('&'))     # ampersands

        # -------- 2) Protocol features (3) --------
        features.append(1 if url.startswith('https://') else 0)
        features.append(1 if url.startswith('http://') else 0)
        features.append(1 if 'https' in url_lower else 0)

        # -------- 3) Suspicious keyword count (1) --------
        suspicious_keywords = [
            'login', 'verify', 'bank', 'secure', 'account',
            'update', 'confirm', 'suspend', 'click', 'here',
            'free', 'win', 'prize', 'urgent', 'limited',
            'password', 'reset', 'unlock', 'activate', 'validate',
            'security', 'alert', 'warning', 'expired', 'locked',
        ]
        keyword_count = sum(1 for k in suspicious_keywords if k in url_lower)
        features.append(keyword_count)

        # -------- 4) Extra phishing pattern features (3) --------
        url_shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
        features.append(1 if any(s in url_lower for s in url_shorteners) else 0)

        has_multiple_suspicious = keyword_count > 2 and url.count('-') > 2
        features.append(1 if has_multiple_suspicious else 0)

        suspicious_path_patterns = ['/login', '/verify', '/secure', '/account', '/update']
        parsed = self._safe_urlparse(url)
        if parsed is not None:
            path_lower = (parsed.path or '').lower()
            features.append(1 if any(p in path_lower for p in suspicious_path_patterns) else 0)
        else:
            features.append(0)

        # -------- 5) Domain features (8) --------
        try:
            parsed2 = parsed if parsed is not None else urlparse(self._normalize_url(url))
            domain = parsed2.netloc or (parsed2.path.split('/')[0] if parsed2.path else '')
            domain_lower = domain.lower()

            features.append(len(domain))        # domain length
            features.append(domain.count('.'))  # dot count in domain

            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            features.append(1 if re.search(ip_pattern, domain) else 0)

            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click']
            features.append(1 if any(tld in domain_lower for tld in suspicious_tlds) else 0)

            common_domains = [
                'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal',
                'netflix', 'twitter', 'instagram', 'linkedin', 'ebay', 'yahoo',
            ]
            features.append(1 if any(cd in domain_lower for cd in common_domains) else 0)

            typosquatting_patterns = [
                'go0gle', 'g00gle', 'faceb00k', 'amaz0n', 'micr0soft',
                'paypa1', 'app1e', 'tw1tter', '1nstagram',
            ]
            features.append(1 if any(tp in domain_lower for tp in typosquatting_patterns) else 0)

            subdomain_count = domain.count('.') - 1
            features.append(1 if subdomain_count > 2 else 0)

            features.append(1 if '-' in domain else 0)
        except Exception:
            features.extend([0, 0, 0, 0, 0, 0, 0, 0])

        # -------- 6) Path features (2) --------
        try:
            parsed3 = parsed if parsed is not None else urlparse(self._normalize_url(url))
            path = parsed3.path or ''
            features.append(len(path))
            features.append(path.count('/'))
        except Exception:
            features.extend([0, 0])

        # -------- 7) Query features (2) --------
        try:
            parsed4 = parsed if parsed is not None else urlparse(self._normalize_url(url))
            query = parsed4.query or ''
            features.append(len(query))
            features.append(query.count('&'))
        except Exception:
            features.extend([0, 0])

        # -------- 8) Port feature (1) --------
        try:
            parsed5 = parsed if parsed is not None else urlparse(self._normalize_url(url))
            port = parsed5.port
            features.append(1 if port and port not in [80, 443] else 0)
        except Exception:
            features.append(0)

        # -------- 9) Character ratio features (2) --------
        length = len(url) if len(url) > 0 else 1
        digit_count = sum(1 for c in url if c.isdigit())
        letter_count = sum(1 for c in url if c.isalpha())
        features.append(digit_count / length)
        features.append(letter_count / length)

        return np.array(features)
    
    def generate_training_data(self):
        """
        Generate synthetic training data based on common phishing patterns
        """
        # Safe URLs
        safe_urls = [
            'https://www.google.com',
            'https://www.github.com',
            'https://www.stackoverflow.com',
            'https://www.wikipedia.org',
            'https://www.microsoft.com',
            'https://www.apple.com',
            'https://www.amazon.com',
            'https://www.facebook.com',
            'https://www.twitter.com',
            'https://www.linkedin.com',
            'https://www.youtube.com',
            'https://www.reddit.com',
            'https://www.netflix.com',
            'https://www.spotify.com',
            'https://www.paypal.com',
            'https://www.ebay.com',
            'https://www.etsy.com',
            'https://www.medium.com',
            'https://www.quora.com',
            'https://www.dropbox.com',
            'https://www.google.com/search?q=test',
            'https://www.github.com/user/repo',
            'https://www.stackoverflow.com/questions/123',
            'https://www.wikipedia.org/wiki/Test',
            'https://www.microsoft.com/en-us',
        ]
        
        # Phishing URLs (common patterns)
        phishing_urls = [
            'http://www.google.com-login.verify.tk',
            'https://secure-bank-update.tk/verify',
            'https://www.paypal.com-suspend.ml/account',
            'http://facebook.com-verify.ga/login',
            'https://amazon.com-update.cf/confirm',
            'http://192.168.1.1/login',
            'https://www.google.com.verify.tk',
            'http://microsoft-update.ml/secure',
            'https://apple-id-verify.ga/account',
            'http://paypal-suspend.tk/update',
            'https://www.bank-verify.tk/login',
            'http://secure-update.ml/account',
            'https://www.google.com-login.tk',
            'http://facebook-verify.ga/confirm',
            'https://amazon-update.cf/suspend',
            'https://www.paypal.com.verify.ml',
            'http://microsoft-secure.tk/update',
            'https://apple-verify.ga/account',
            'http://bank-update.ml/login',
            'https://www.google.com-suspend.tk',
            'http://facebook.com-verify.ga',
            'https://amazon.com-update.cf/secure',
            'http://paypal-verify.tk/account',
            'https://www.microsoft.com-update.ml',
            'https://www.google.com/login?redirect=evil.com',
            'http://www.paypal.com@evil.com',
            'https://www.facebook.com.verify.tk/login',
        ]
        
        X = []
        y = []
        
        for url in safe_urls:
            X.append(self.extract_features(url))
            y.append(0)  # Safe
        
        for url in phishing_urls:
            X.append(self.extract_features(url))
            y.append(1)  # Phishing
        
        return np.array(X), np.array(y)
    
    def train_model(self):
        """Train the ML model"""
        print("Generating training data...")
        X, y = self.generate_training_data()
        
        print(f"Training on {len(X)} samples...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model accuracy: {accuracy:.2%}")
        
        # Save model
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"Model saved to {self.model_path}")
    
    def load_or_train_model(self):
        """Load existing model or train a new one"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print(f"Model loaded from {self.model_path}")
            except:
                print("Failed to load model, training new one...")
                self.train_model()
        else:
            print("No existing model found, training new one...")
            self.train_model()
    
    def predict(self, url):
        """
        Predict if URL is phishing
        Returns: (is_phishing: bool, confidence: float)
        """
        if self.model is None:
            self.load_or_train_model()
        
        features = self.extract_features(url).reshape(1, -1)
        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        
        is_phishing = bool(prediction)
        confidence = float(probabilities[1] if is_phishing else probabilities[0])
        
        return is_phishing, confidence
