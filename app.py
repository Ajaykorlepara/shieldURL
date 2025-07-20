import pickle
import numpy as np
import re
from urllib.parse import urlparse as url_parse
from tld import get_tld
from fastapi import FastAPI
from pydantic import BaseModel

# Initialize FastAPI app
app = FastAPI(title="Malicious URL Checker API", description="API to predict if a URL is malicious, benign, phishing, or defacement.")

# --- Load Saved Model and Scaler ---
# Make sure these .pkl files are in the same directory as your app.py
try:
    model = pickle.load(open("model.pkl", "rb"))
    scaler = pickle.load(open("scaler.pkl", "rb"))
    label_encoder = pickle.load(open("label_encoder.pkl", "rb"))
except FileNotFoundError as e:
    raise RuntimeError("Model or scaler files not found. Ensure model.pkl, scaler.pkl, and label_encoder.pkl are present.") from e


# --- Feature Extraction Functions (Copied from your notebook) ---
def having_ip_address(url):
    match = re.search(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    return 1 if match else 0

def abnormal_url(url):
    parsed_url = url_parse(url)
    hostname = parsed_url.hostname or ""
    return 1 if hostname in url else 0

def count_dot(url): return url.count('.')
def count_www(url): return url.count('www')
def count_atrate(url): return url.count('@')
def no_of_dir(url): return url_parse(url).path.count('/')
def no_of_embed(url): return url_parse(url).path.count('//')

def shortening_service(url):
    pattern = r'bit\.ly|goo\.gl|shorte\.st|x\.co|ow\.ly|tinyurl|t\.co'
    return 1 if re.search(pattern, url) else 0

def count_https(url): return url.count('https')
def count_http(url): return url.count('http')
def count_per(url): return url.count('%')
def count_ques(url): return url.count('?')
def count_hyphen(url): return url.count('-')
def count_equal(url): return url.count('=')
def url_length(url): return len(url)
def hostname_length(url): return len(url_parse(url).netloc)
def suspicious_words(url):
    return 1 if re.search(r'PayPal|login|signin|bank|account|update|free|bonus', url, re.IGNORECASE) else 0

def digit_count(url): return sum(c.isdigit() for c in url)
def letter_count(url): return sum(c.isalpha() for c in url)
def fd_length(url): return len(url_parse(url).path.split('/')[1]) if '/' in url_parse(url).path else 0
def tld_length(tld): return len(tld) if tld else -1


# --- Preprocessing Function ---
def preprocess_url(url):
    # This list comprehensions creates the feature vector
    features = [
        having_ip_address(url), abnormal_url(url), count_dot(url), count_www(url), count_atrate(url),
        no_of_dir(url), no_of_embed(url), shortening_service(url), count_https(url), count_http(url),
        count_per(url), count_ques(url), count_hyphen(url), count_equal(url), url_length(url),
        hostname_length(url), suspicious_words(url), digit_count(url), letter_count(url), fd_length(url),
        tld_length(get_tld(url, fail_silently=True))
    ]
    # The feature order must be identical to the order used during training
    # Your original code had 21 features going into the model. Let's adjust to match.
    # Original columns: ['use_of_ip','abnormal_url','count.','count-www','count@','count_dir','count_embed_domian','short_url','count-https','count-http','count%','count?','count-','count=','url_length','hostname_length','sus_url','fd_length','tld_length','count-digits','count-letters']
    # The order seems slightly different in your training code vs preprocess_url function. Let's fix that.
    
    # Correct feature vector based on your training columns:
    # Note: `tld` itself isn't a feature, `tld_length` is.
    tld_val = get_tld(url, fail_silently=True)
    
    final_features = [
        having_ip_address(url),
        abnormal_url(url),
        count_dot(url),
        count_www(url),
        count_atrate(url),
        no_of_dir(url),
        no_of_embed(url),
        shortening_service(url),
        count_https(url),
        count_http(url),
        count_per(url),
        count_ques(url),
        count_hyphen(url),
        count_equal(url),
        url_length(url),
        hostname_length(url),
        suspicious_words(url),
        fd_length(url),
        tld_length(tld_val),
        digit_count(url),
        letter_count(url)
    ]
    return final_features

# --- API Data Models ---
# This defines the structure of the request body
class URLRequest(BaseModel):
    url: str

# This defines the structure of the response
class PredictionResponse(BaseModel):
    url: str
    prediction: str


# --- API Endpoints ---
@app.get("/", summary="Root endpoint to check API status")
def read_root():
    """Check if the API is running."""
    return {"status": "ok", "message": "URL Checker API is running."}


@app.post("/predict", response_model=PredictionResponse, summary="Predict URL Type")
def predict_url_type(request: URLRequest):
    """
    Accepts a URL and predicts its type (benign, phishing, etc.).
    - **url**: The URL to be classified.
    """
    url_to_check = request.url
    
    # Preprocess the URL and create the feature vector
    features = preprocess_url(url_to_check)
    
    # Reshape for the scaler and model
    features_reshaped = np.array(features).reshape(1, -1)
    
    # Scale the features
    features_scaled = scaler.transform(features_reshaped)
    
    # Make a prediction
    prediction_encoded = model.predict(features_scaled)
    
    # Decode the prediction to the original label
    prediction_label = label_encoder.inverse_transform(prediction_encoded)[0]
    
    return {"url": url_to_check, "prediction": prediction_label}