from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix

import pandas as pd
import math
import tldextract
import Levenshtein
import re
import joblib

from collections import Counter



data = pd.read_csv("phishing_site_urls.csv")

#clean data
data.drop_duplicates(inplace=True)
data.dropna(inplace=True)
# convert labels -> numbers

data["Label"] = data["Label"].map({

    "good": 0,
    "bad": 1
})



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

    maximum_similarity = 0

    for brand in trusted_brands:

        similarity = Levenshtein.ratio(
            domain,
            brand
        )

        if similarity > maximum_similarity:

            maximum_similarity = similarity

    return maximum_similarity



shorteners = [

    'bit.ly',
    'tinyurl',
    'goo.gl',
    't.co',
    'is.gd'
]


bad_tlds = [

    'ru',
    'tk',
    'ml',
    'ga',
    'cf',
    'gq'
]


def extract_feature(url):

    ext = tldextract.extract(url)

    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain

    url_entropy = calculate_entropy(url)

    typo_score = typosquat_score(domain)

    return {

        'length':
        len(url),

        'domain_length':
        len(domain),

        'dots':
        url.count('.'),

        'hyphens':
        url.count('-'),

        'slashes':
        url.count('/'),

        'digits':
        sum(c.isdigit() for c in url),

        'special_chars':
        sum(not c.isalnum() for c in url),

        'subdomain_count':
        len(subdomain.split('.')) if subdomain else 0,

        'https':
        int(url.startswith('https://')),

        'http':
        int(url.startswith('http://')),

        'logins':
        url.lower().count('login'),

        'verify':
        url.lower().count('verify'),

        'password':
        url.lower().count('password'),

        'secure':
        url.lower().count('secure'),

        'confirm':
        url.lower().count('confirm'),

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

        'bad_tld':
        int(suffix in bad_tlds),

        'shortened':
        int(any(s in url for s in shorteners)),

        'ip_address':
        int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),

        'double_slash':
        int('//' in url[8:]),

        'url_entropy':
        url_entropy,

        'typo_score':
        typo_score
    }

X_features = []
urls = []
y = []

for index, row in data.iterrows():

    url = str(row["URL"])

    label = row["Label"]

    features = extract_feature(url)

    X_features.append([

        features["length"],
        features["domain_length"],
        features["dots"],
        features["hyphens"],
        features["slashes"],
        features["digits"],
        features["special_chars"],
        features["subdomain_count"],
        features["https"],
        features["http"],
        features["logins"],
        features["verify"],
        features["password"],
        features["secure"],
        features["confirm"],
        features["fake_google"],
        features["fake_amazon"],
        features["fake_paypal"],
        features["fake_facebook"],
        features["fake_microsoft"],
        features["bad_tld"],
        features["shortened"],
        features["ip_address"],
        features["double_slash"],
        features["url_entropy"],
        features["typo_score"]

    ])

    urls.append(url)

    y.append(label)

vectorizer = TfidfVectorizer(

    analyzer='char',
    ngram_range=(3, 5),
    max_features=5000
)

X_tfidf = vectorizer.fit_transform(urls)

X_features_sparse = csr_matrix(X_features)

X = hstack([X_features_sparse, X_tfidf])


X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

model = XGBClassifier(

    n_estimators=500,
    max_depth=10,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    eval_metric='logloss',
    n_jobs=-1
)



model.fit(X_train, y_train)



predictions = model.predict(X_test)



accuracy = accuracy_score(y_test, predictions)

print("\nAccuracy:\n")
print(accuracy)

print("\nClassification Report:\n")
print(classification_report(y_test, predictions))




joblib.dump(model, "phishing_model.pkl")

joblib.dump(vectorizer, "tfidf_vectorizer.pkl")

print("\nModel saved successfully")