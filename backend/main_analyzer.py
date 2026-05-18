import joblib
import tldextract
import math
import Levenshtein
import re

from collections import Counter
from urllib.parse import unquote

from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix

from url_decoder import decode_url
from dns_lookup import dns_lookup
from whois_lookup import whois_lookup

# =========================
# LOAD MODEL + TFIDF
# =========================

model = joblib.load(
    "phishing_model.pkl"
)

vectorizer = joblib.load(
    "tfidf_vectorizer.pkl"
)

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

def extract_feature(url):

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

    # COMBINE FEATURES
    handcrafted_sparse = csr_matrix(
        handcrafted_features
    )

    combined_features = hstack([

        handcrafted_sparse,
        tfidf_features

    ])

    return combined_features

# =========================
# USER INPUT
# =========================

url = input("Enter URL: ")

# =========================
# URL DECODING
# =========================

decoded_url = decode_url(url)

# =========================
# FEATURE EXTRACTION
# =========================

features = extract_feature(
    decoded_url
)

# =========================
# MODEL PREDICTION
# =========================

prediction = model.predict(
    features
)

probability = float(

    model.predict_proba(features)[0][1]

)

# =========================
# DNS LOOKUP
# =========================

dns_info = dns_lookup(url)

# =========================
# WHOIS LOOKUP
# =========================

whois_info = whois_lookup(url)

# =========================
# FINAL OUTPUT
# =========================

print("\n========== ANALYSIS ==========")

print("\nPrediction:")

if prediction[0] == 1:

    print("Phishing URL")

else:

    print("Safe URL")

print("\nConfidence Score:")

print(
    round(probability * 100, 2),
    "%"
)

print("\nDecoded URL:")

print(decoded_url)

print("\nEntropy Score:")

print(
    calculate_entropy(decoded_url)
)

print("\nDNS Information:")

print(dns_info)

print("\nWHOIS Information:")

print(whois_info)