from flask import Flask, request, jsonify
from flask_cors import CORS

import joblib
import math
import re
import tldextract
import Levenshtein

from collections import Counter
from urllib.parse import urlparse

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/*": {
            "origins": "*"
        }
    }
)

# LOAD MODEL
model = joblib.load("phishing_model.pkl")

# TRUSTED DOMAINS
TRUSTED_DOMAINS = [
    "google.com",
    "youtube.com",
    "chatgpt.com",
    "openai.com",
    "github.com",
    "microsoft.com"
]

# TRUSTED BRANDS
trusted_brands = [
    'google',
    'amazon',
    'paypal',
    'facebook',
    'microsoft',
    'apple',
    'netflix',
    'instagram',
    'linkedin',
    'github'
]

# ENTROPY FUNCTION
def calculate_entropy(text):

    counter = Counter(text)

    length = len(text)

    entropy = 0

    for count in counter.values():

        probability = count / length

        entropy -= (
            probability *
            math.log2(probability)
        )

    return entropy


# TYPOSQUATTING SCORE
def typosquat_score(domain):

    minimum_distance = 999

    for brand in trusted_brands:

        distance = Levenshtein.distance(
            domain,
            brand
        )

        if distance < minimum_distance:

            minimum_distance = distance

    return minimum_distance


# FEATURE EXTRACTION
def extract_features(url):

    ext = tldextract.extract(url)

    domain = ext.domain
    subdomain = ext.subdomain

    url_entropy = calculate_entropy(url)

    typo_score = typosquat_score(domain)

    features = [

        len(url),
        url.count('.'),
        url.count('-'),

        url.count('login'),
        url.count('verify'),
        url.count('123'),
        url.count('cloud'),
        url.count('password'),
        url.count('secure'),
        url.count('confirm'),
        url.count('999'),

        url.count('http://'),

        int(
            ('google' in url)
            and ('google.com' not in url)
        ),

        int(
            ('amazon' in url)
            and ('amazon.com' not in url)
            and ('amazon.in' not in url)
        ),

        int(
            ('paypal' in url)
            and ('paypal.com' not in url)
        ),

        int(
            ('facebook' in url)
            and ('facebook.com' not in url)
        ),

        int(
            ('microsoft' in url)
            and ('microsoft.com' not in url)
        ),

        int(url.endswith('.ru')),

        url.count('/'),

        sum(c.isdigit() for c in url),

        sum(not c.isalnum() for c in url),

        len(subdomain.split('.'))
        if subdomain else 0,

        url_entropy,

        typo_score
    ]

    return [features]


# HOME ROUTE
@app.route("/")
def home():

    return "PhishGuard backend running!"


# ANALYZE ROUTE
@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data or "url" not in data:

        return jsonify({
            "error": "URL missing"
        }), 400

    url = data["url"]

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    domain = domain.replace("www.", "")

    # EXTRACT FEATURES
    features = extract_features(url)

    # MODEL PREDICTION
    prediction = model.predict(features)[0]

    # MODEL PROBABILITY
    probability = float(
        model.predict_proba(features)[0][1]
    )

    # RISK SCORE
    risk_score = max(
        1,
        int((probability ** 2) * 100)
    )

    # TRUSTED DOMAIN CLAMP
    for trusted in TRUSTED_DOMAINS:

        if trusted in domain:

            risk_score = min(risk_score, 3)

            break

    # LABEL
    if risk_score >= 60:

        label = "PHISHING"

    else:

        label = "SAFE"

    # REASONS
    reasons = []

    if "login" in url.lower():

        reasons.append(
            "Contains login keyword"
        )

    if url.count("-") >= 3:

        reasons.append(
            "Too many hyphens"
        )

    if len(url) > 100:

        reasons.append(
            "Very long URL"
        )

    if not url.startswith("https"):

        reasons.append(
            "No HTTPS encryption"
        )

    if len(reasons) == 0:

        reasons.append(
            "No major phishing indicators detected"
        )

    return jsonify({

        "url": url,
        "prediction": label,
        "risk_score": risk_score,
        "confidence": risk_score,
        "reasons": reasons
    })


if __name__ == "__main__":

    app.run(debug=True)


# from flask import Flask, request, jsonify
# from flask_cors import CORS

# import joblib
# import math
# import re

# from urllib.parse import urlparse

# app = Flask(__name__)
# CORS(
#     app,
#     resources={
#         r"/*": {
#             "origins": "*"
#         }
#     }
# )

# # Load trained ML model
# model = joblib.load("phishing_model.pkl")
# print("Model expects", model.n_features_in_, "features")

# # Trusted domains
# TRUSTED_DOMAINS = [
#     "google.com",
#     "youtube.com",
#     "chatgpt.com",
#     "openai.com",
#     "github.com",
#     "microsoft.com"
# ]

# # Extract simple URL features
# def extract_features(url):

#     features = []

#     # URL length
#     features.append(len(url))

#     # Count dots
#     features.append(url.count("."))

#     # Count hyphens
#     features.append(url.count("-"))

#     # Has HTTPS
#     features.append(1 if url.startswith("https") else 0)

#     # Count special chars
#     features.append(len(re.findall(r"[!@#$%^&*(),?\":{}|<>]", url)))

#     return features  

# # Home route
# @app.route("/")
# def home():
#     return "PhishGuard backend running!"

# # Analyze route
# @app.route("/analyze", methods=["POST"])
# def analyze():

#     data = request.get_json()

#     if not data or "url" not in data:
#         return jsonify({
#             "error": "URL missing"
#         }), 400

#     url = data["url"]

#     parsed = urlparse(url)
#     domain = parsed.netloc.lower()

#     # Remove www.
#     domain = domain.replace("www.", "")

#     # Extract features
#     features = extract_features(url)

#     print("Generated features:", len(features))
#     print("Features:", features)
#     # Predict
#     prediction = model.predict(features)[0]

#     # Probability
#     probability = float(
#         model.predict_proba(features)[0][1]
#     )

#     # Better calibrated score
#     risk_score = max(
#         1,
#         int((probability ** 2) * 100)
#     )

#     # Clamp trusted domains
#     for trusted in TRUSTED_DOMAINS:

#         if trusted in domain:

#             risk_score = min(risk_score, 3)

#             break

#     # Prediction label
#     if risk_score >= 60:
#         label = "PHISHING"
#     else:
#         label = "SAFE"

#     reasons = []

#     if "login" in url.lower():
#         reasons.append(
#             "Contains login keyword"
#         )

#     if url.count("-") >= 3:
#         reasons.append(
#             "Too many hyphens"
#         )

#     if len(url) > 100:
#         reasons.append(
#             "Very long URL"
#         )

#     if not url.startswith("https"):
#         reasons.append(
#             "No HTTPS encryption"
#         )

#     if len(reasons) == 0:
#         reasons.append(
#             "No major phishing indicators detected"
#         )

#     return jsonify({
#         "url": url,
#         "prediction": label,
#         "risk_score": risk_score,
#         "confidence": risk_score,
#         "reasons": reasons
#     })

# if __name__ == "__main__":
#     app.run(debug=True)
    
