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

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body must be an object"}), 400

    # ignore index/Result if client sends them
    data.pop("index", None)
    data.pop("Result", None)

    missing = [c for c in FEATURE_COLS if c not in data]
    if missing:
        return jsonify({"error": "Missing required features", "missing": missing}), 400

    X = pd.DataFrame([[data[c] for c in FEATURE_COLS]], columns=FEATURE_COLS)

    pred = model.predict(X)[0]
    label = "phishing" if int(pred) == 1 else "legit"  # adjust if your Result mapping differs

    resp = {"label": label, "raw_pred": int(pred)}

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]
        # choose probability for class 1 if present
        if hasattr(model, "classes_") and 1 in list(model.classes_):
            idx = list(model.classes_).index(1)
            resp["probability"] = float(proba[idx])

    return jsonify(resp), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)