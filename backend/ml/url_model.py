import joblib
import os
import re
from urllib.parse import urlparse

# Load model and feature list
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

model = None
try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"Error loading phishing model: {e}")

def extract_features(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except:
        hostname = ""
    
    url_len = len(url)
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    
    # Matching the features used during training:
    # 'URLLength', 'NoOfSubDomain', 'IsHTTPS', 'NoOfLettersInURL', 
    # 'NoOfDegitsInURL', 'NoOfEqualsInURL', 'NoOfQMarkInURL', 
    # 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL'
    features = [
        url_len,
        hostname.count('.'),
        1 if url.startswith('https') else 0,
        letters,
        digits,
        url.count('='),
        url.count('?'),
        url.count('&'),
        url_len - letters - digits
    ]
    return [features]

def url_ml_check(url):
    if model is None:
        # Fallback to simple logic if model not loaded
        if len(url) > 150 or "login" in url.lower():
            return "BLOCK", "heuristic_fallback"
        return "ALLOW", "heuristic_fallback"

    try:
        X = extract_features(url)
        prediction = model.predict(X)[0]
        
        if prediction == 1: # 1 = Phishing
            return "BLOCK", "ml_phishing"
        return "ALLOW", "ml_safe"
    except Exception as e:
        print(f"ML Inference Error: {e}")
        return "ALLOW", "inference_error"