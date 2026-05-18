# PhishGuard

PhishGuard is an AI-powered phishing URL detection system designed to identify malicious websites in real time using machine learning and cybersecurity-based URL intelligence techniques.

The backend combines:

* XGBoost Machine Learning
* TF-IDF URL Pattern Analysis
* Entropy Analysis
* Typosquatting Detection
* WHOIS Intelligence
* DNS Lookup

to detect phishing URLs with high accuracy.

---

# Features

* Real-time phishing URL detection
* XGBoost based classification
* TF-IDF character-level URL analysis
* Entropy-based suspicious URL detection
* Typosquatting detection using Levenshtein similarity
* WHOIS domain intelligence lookup
* DNS resolution analysis
* Risk score generation
* Flask backend API integration

---

# Backend Workflow

1. URL decoding
2. Feature extraction
3. Entropy calculation
4. TF-IDF vectorization
5. Typosquatting analysis
6. XGBoost prediction
7. Risk score generation
8. WHOIS & DNS intelligence retrieval

---

# Accuracy Progression

| Model Stage                                 | Accuracy |
| ------------------------------------------- | -------- |
| Initial RandomForest Model                  | ~79%     |
| Improved RandomForest + Feature Engineering | ~92%     |
| Final XGBoost + TF-IDF Model                | ~95–97%  |

---

# Technologies Used

* Python
* Flask
* XGBoost
* Scikit-learn
* SciPy
* TLDExtract
* Levenshtein
* WHOIS
* DNS Resolver

---

# Model Files

Due to GitHub file size limitations, the trained model files are hosted externally.

Model Files:

[Dropbox Model Files](https://www.dropbox.com/scl/fo/5kvj6t71qbq8ri9nlmklz/AIqqeikRGCOqkewf4KaTfyI?rlkey=zawn7rjo1ilkz7dper0pmv71j&st=4orutmmo&dl=1)

Included files:

* phishing_model.pkl
* tfidf_vectorizer.pkl

---

# Run Backend

```bash
pip install -r requirements.txt
python app.py
```

---

# Project Structure

backend/
│
├── app.py
├── test(XGBoost).py
├── main_analyzer.py
├── dns_lookup.py
├── whois_lookup.py
├── url_decoder.py
├── phishing_model.pkl
├── tfidf_vectorizer.pkl

---

# Conclusion

PhishGuard demonstrates how machine learning and cybersecurity concepts can be combined to build an intelligent real-time phishing detection backend system capable of detecting sophisticated phishing URLs with high accuracy.
