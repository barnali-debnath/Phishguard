import joblib
import tldextract
import math
import Levenshtein

from collections import Counter
from urllib.parse import unquote

from url_decoder import decode_url
from dns_lookup import dns_lookup
from whois_lookup import whois_lookup


# LOAD TRAINED MODEL
model = joblib.load(
    "phishing_model.pkl"
)


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
def extract_feature(url):

    ext = tldextract.extract(url)

    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain

    url_entropy = calculate_entropy(url)

    typo_score = typosquat_score(domain)

    return [

        # BASIC FEATURES
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('/'),

        # KEYWORD FEATURES
        url.count('login'),
        url.count('verify'),
        url.count('123'),
        url.count('cloud'),
        url.count('password'),
        url.count('secure'),
        url.count('confirm'),
        url.count('999'),

        # HTTP FEATURE
        url.count('http://'),

        # STRUCTURAL FEATURES
        sum(c.isdigit() for c in url),

        sum(not c.isalnum() for c in url),

        len(subdomain.split('.'))
        if subdomain else 0,

        # BRAND IMPERSONATION
        int(
            ('google' in url)
            and (domain != 'google')
        ),

        int(
            ('amazon' in url)
            and (domain != 'amazon')
        ),

        int(
            ('paypal' in url)
            and (domain != 'paypal')
        ),

        int(
            ('facebook' in url)
            and (domain != 'facebook')
        ),

        int(
            ('microsoft' in url)
            and (domain != 'microsoft')
        ),

        # TLD FEATURE
        int(url.endswith('.ru')),

        # PHASE 3
        url_entropy,

        # PHASE 4
        typo_score
    ]


# USER INPUT
url = input("Enter URL: ")


# URL DECODING
decoded_url = decode_url(url)


# FEATURE EXTRACTION
features = extract_feature(
    decoded_url
)


# MODEL PREDICTION
prediction = model.predict(
    [features]
)


# DNS LOOKUP
dns_info = dns_lookup(url)


# WHOIS LOOKUP
whois_info = whois_lookup(url)


# FINAL OUTPUT
print("\n========== ANALYSIS ==========")

print("\nPrediction:")

if prediction[0] == 'bad':

    print("Phishing URL")

else:

    print("Safe URL")


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

