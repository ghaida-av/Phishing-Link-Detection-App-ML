
import requests
import json

BASE_URL = "http://localhost:5001"

def test_predict(url_input):
    """Test the /predict endpoint"""
    print(f"\n{'='*60}")
    print(f"Testing: {url_input}")
    print(f"{'='*60}")
    
    response = requests.post(
        f"{BASE_URL}/predict",
        json={"url": url_input},
        headers={"Content-Type": "application/json"}
    )
    
    print(f"Status Code: {response.status_code}")
    result = response.json()
    print(f"Response: {json.dumps(result, indent=2)}")
    return result

def test_stats():
    """Test the /stats endpoint"""
    print(f"\n{'='*60}")
    print("Testing /stats endpoint")
    print(f"{'='*60}")
    
    response = requests.get(f"{BASE_URL}/stats")
    print(f"Status Code: {response.status_code}")
    result = response.json()
    print(f"Response: {json.dumps(result, indent=2)}")

def test_recent():
    """Test the /recent endpoint"""
    print(f"\n{'='*60}")
    print("Testing /recent endpoint")
    print(f"{'='*60}")
    
    response = requests.get(f"{BASE_URL}/recent?limit=5")
    print(f"Status Code: {response.status_code}")
    result = response.json()
    print(f"Response: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    print("Testing Phishing Detection API")
    print("Is Flask server is running on port 5001")
    
  
    test_cases = [
        "https://www.google.com",  
        "https://www.google.com-login.verify.tk", 
        "test@example.com",  
        "https://www.github.com",  
        "http://192.168.1.1/login", 
        "invalid-input-123", 
    ]
    
    for test_case in test_cases:
        test_predict(test_case)
    
   
    test_stats()
    
   
    test_recent()
    
    print("\n" + "="*60)
    print("Testing complete!")
    print("="*60)
