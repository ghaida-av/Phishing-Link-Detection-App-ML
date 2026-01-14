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
    
    def extract_features(self, url):
        """
        Extract features from URL for ML model
        Returns a feature vector
        """
        features = []
        
        # Basic URL features
        features.append(len(url))  # URL length
        features.append(url.count('.'))  # Number of dots
        features.append(url.count('-'))  # Number of hyphens
        features.append(url.count('_'))  # Number of underscores
        features.append(url.count('/'))  # Number of slashes
        features.append(url.count('?'))  # Number of question marks
        features.append(url.count('='))  # Number of equals signs
        features.append(url.count('@'))  # Number of @ symbols
        features.append(url.count('&'))  # Number of ampersands
        
        # Protocol features
        features.append(1 if url.startswith('https://') else 0)
        features.append(1 if url.startswith('http://') else 0)
        features.append(1 if 'https' in url.lower() else 0)
        
        # Suspicious keywords
        suspicious_keywords = ['login', 'verify', 'bank', 'secure', 'account', 
                              'update', 'confirm', 'suspend', 'click', 'here',
                              'free', 'win', 'prize', 'urgent', 'limited']
        keyword_count = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
        features.append(keyword_count)
        
        # Domain features
        try:
            parsed = urlparse(url if '://' in url else 'http://' + url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            features.append(len(domain))  # Domain length
            features.append(domain.count('.'))  # Subdomain count
            
            # Check for IP address in domain
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            features.append(1 if re.search(ip_pattern, domain) else 0)
            
            # Check for suspicious TLD
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
            features.append(1 if any(tld in domain.lower() for tld in suspicious_tlds) else 0)
            
            # Check for homoglyph/typosquatting (simplified)
            common_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal']
            features.append(1 if any(cd in domain.lower() for cd in common_domains) else 0)
            
        except:
            features.extend([0, 0, 0, 0, 0])
        
        # Path features
        try:
            parsed = urlparse(url if '://' in url else 'http://' + url)
            path = parsed.path
            features.append(len(path))
            features.append(path.count('/'))
        except:
            features.extend([0, 0])
        
        # Query string features
        try:
            parsed = urlparse(url if '://' in url else 'http://' + url)
            query = parsed.query
            features.append(len(query))
            features.append(query.count('&'))
        except:
            features.extend([0, 0])
        
        # Port number
        try:
            parsed = urlparse(url if '://' in url else 'http://' + url)
            port = parsed.port
            features.append(1 if port and port not in [80, 443] else 0)
        except:
            features.append(0)
        
        # Digit ratio
        digit_count = sum(1 for c in url if c.isdigit())
        features.append(digit_count / len(url) if len(url) > 0 else 0)
        
        # Letter ratio
        letter_count = sum(1 for c in url if c.isalpha())
        features.append(letter_count / len(url) if len(url) > 0 else 0)
        
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
