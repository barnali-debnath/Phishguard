from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import pandas as pd
import math
import tldextract
import Levenshtein
from collections import Counter



data = pd.read_csv("phishing_site_urls.csv")

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


def extract_feature(url):
    ext = tldextract.extract(url)

    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain
    url_entropy = calculate_entropy(url)
    typo_score = typosquat_score(domain)
    return {
        'length':len(url),
        'dots':url.count('.'),
        'hyphens': url.count('-'),
        'logins': url.count('login'),
        'verify': url.count('verify'),
        '123' : url.count('123'),
        'cloud' : url.count('cloud'),
        'password' : url.count('password'),
        'secure' : url.count('secure'),
        'confirm' : url.count('confirm'),
        '999' : url.count('999'),
        'http://' : url.count('http://'),
        'slashes': url.count('/'),
        'digits': sum(c.isdigit() for c in url),
        'special_chars':
        sum(not c.isalnum() for c in url),
        'subdomain_count':
        len(subdomain.split('.')) if subdomain else 0,
        'fake_google':
        int(('google' in url) and ('google.com' not in url)),

        'fake_amazon':
        int(('amazon' in url) and ('amazon.com' not in url) and ('amazon.in' not in url)),

        'fake_paypal':
        int(('paypal' in url) and ('paypal.com' not in url)),

        'fake_facebook':
        int(('facebook' in url) and ('facebook.com' not in url)),

        'fake_microsoft':
        int(('microsoft' in url) and ('microsoft.com' not in url)),
        'ru_domain' : int(url.endswith('.ru')),
        'url_entropy': url_entropy,
        'typo_score': typo_score,
    }

X = []
y = []




for index, row in data.iterrows():
    url = row["URL"]
    label = row["Label"]
    features = extract_feature(url)
    X.append([
    features["length"],
    features["dots"],
    features["hyphens"],
    features["logins"],
    features["verify"],
    features["123"],
    features["cloud"],
    features["password"],
    features["secure"],
    features["confirm"],
    features["999"],
    features["http://"],
    features["fake_google"],
    features["fake_amazon"],
    features["fake_paypal"],
    features["fake_facebook"],
    features["fake_microsoft"],
    features["ru_domain"],
    features['slashes'],
    features['digits'],
    features['special_chars'],
    features['subdomain_count'],
    features["url_entropy"],
    features["typo_score"],
    ])
    y.append(label)
    
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

model = RandomForestClassifier()
model.fit(X_train, y_train)
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(accuracy)

import joblib

joblib.dump(
    model,
    "phishing_model.pkl"
)
import pickle

with open(
    "phishing_model.pkl",
    "wb"
) as file:

    pickle.dump(model, file)

print("Model saved successfully")

    
#print(X[:5])
#print(y[:5])
    
