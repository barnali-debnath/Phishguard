from flask import Flask, request, jsonify
from flask_cors import CORS

import joblib
import math
import re
import tldextract
import Levenshtein

from collections import Counter
from urllib.parse import urlparse

from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/*": {
            "origins": "*"
        }
    }
)

# =========================
# LOAD MODEL + TFIDF
# =========================

model = joblib.load("phishing_model.pkl")

vectorizer = joblib.load(
    "tfidf_vectorizer.pkl"
)

# =========================
# TRUSTED DOMAINS
# =========================

TRUSTED_DOMAINS = [

    "google.com",
    "youtube.com",
    "chatgpt.com",
    "openai.com",
    "github.com",
    "microsoft.com"
]

# =========================
# TRUSTED BRANDS
# =========================

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

# =========================
# SHORTENERS
# =========================

shorteners = [

    'bit.ly',
    'tinyurl',
    'goo.gl',
    't.co',
    'is.gd'
]

# =========================
# BAD TLDS
# =========================

bad_tlds = [

    'ru',
    'tk',
    'ml',
    'ga',
    'cf',
    'gq'
]

# =========================
# ENTROPY FUNCTION
# =========================

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

# =========================
# TYPOSQUATTING SCORE
# =========================

def typosquat_score(domain):

    maximum_similarity = 0

    for brand in trusted_brands:

        similarity = Levenshtein.ratio(
            domain,
            brand
        )

        if similarity > maximum_similarity:

            maximum_similarity = similarity

    return maximum_similarity

# =========================
# FEATURE EXTRACTION
# =========================

def extract_features(url):

    ext = tldextract.extract(url)

    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain

    url_entropy = calculate_entropy(url)

    typo_score = typosquat_score(domain)

    handcrafted_features = [[

        len(url),

        len(domain),

        url.count('.'),

        url.count('-'),

        url.count('/'),

        sum(c.isdigit() for c in url),

        sum(not c.isalnum() for c in url),

        len(subdomain.split('.'))
        if subdomain else 0,

        int(url.startswith('https://')),

        int(url.startswith('http://')),

        url.lower().count('login'),

        url.lower().count('verify'),

        url.lower().count('password'),

        url.lower().count('secure'),

        url.lower().count('confirm'),

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

        int(suffix in bad_tlds),

        int(any(s in url for s in shorteners)),

        int(bool(
            re.search(
                r'\d+\.\d+\.\d+\.\d+',
                url
            )
        )),

        int('//' in url[8:]),

        url_entropy,

        typo_score
    ]]

    # TF-IDF FEATURES
    tfidf_features = vectorizer.transform([url])

    # COMBINE BOTH
    handcrafted_sparse = csr_matrix(
        handcrafted_features
    )

    combined_features = hstack([

        handcrafted_sparse,
        tfidf_features

    ])

    return combined_features

# =========================
# HOME ROUTE
# =========================

@app.route("/")
def home():

    return "PhishGuard backend running!"

# =========================
# ANALYZE ROUTE
# =========================

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

            risk_score = min(
                risk_score,
                3
            )

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

    if risk_score >= 80:

        reasons.append(
            "High phishing probability detected"
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

# =========================
# RUN SERVER
# =========================

if __name__ == "__main__":

    app.run(debug=True)