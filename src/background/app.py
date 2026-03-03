from flask import Flask, request, jsonify, render_template
import pickle
import numpy as np
import pandas as pd

app = Flask(__name__)

with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
    
FEATURE_COLS = [
    "having_IPhaving_IP_Address",
    "URLURL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

@app.route('/')
def home():
    return render_template('index.html')

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "JSON body must be an object"}), 400

        # Allow client to send extra keys like index/Result; ignore them safely.
        # Build a 1-row dataframe with strict column order.
        row = {}
        missing = []
        for col in FEATURE_COLS:
            if col in data:
                row[col] = data[col]
            else:
                missing.append(col)

        if missing:
            return jsonify({
                "error": "Missing required features",
                "missing": missing
            }), 400

        X = pd.DataFrame([row], columns=FEATURE_COLS)

        # RandomForest supports predict_proba for classifiers
        prob = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X)
            # Some datasets encode phishing as 1/-1. Handle both cases.
            # If classes_ exists, pick probability of the "phishing" class.
            if hasattr(model, "classes_"):
                classes = list(model.classes_)
                # Prefer class 1 if present, else max probability class as fallback
                if 1 in classes:
                    idx = classes.index(1)
                elif -1 in classes:
                    idx = classes.index(-1)
                else:
                    idx = int(np.argmax(proba[0]))
                prob = float(proba[0][idx])
            else:
                prob = float(np.max(proba[0]))

        pred = model.predict(X)[0]

        # Normalize prediction to label
        # Common Kaggle phishing labels: 1 (phish) / -1 (legit) or 1/0
        if isinstance(pred, (np.integer, int, float, np.floating)):
            if int(pred) == 1:
                label = "phishing"
            elif int(pred) in (0, -1):
                label = "legit"
            else:
                label = str(pred)
        else:
            label = str(pred)

        # If prob is None, still return label.
        resp = {"label": label}
        if prob is not None:
            resp["probability"] = prob

        return jsonify(resp), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)