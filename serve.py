from fastapi import FastAPI
from pydantic import BaseModel
from joblib import load
import numpy as np
import pandas as pd
import uvicorn
from extract_url import extract_url

model = load("model/phish_feature_model.joblib")
label_encoder = load("model/label_encoder.joblib")

app = FastAPI(title="PhishDetector API")

class URLRequest(BaseModel):
    url: str | None = None
    features: dict | None = None

@app.post("/predict")
def predict(data: URLRequest):
    try:
        # If URL provided, extract features automatically
        if data.url:
            input_dict = extract_url(data.url)
        elif data.features:
            input_dict = data.features
        else:
            return {"error": "No input provided"}

        expected_cols = model.feature_names_in_
        df = pd.DataFrame([[input_dict.get(col, 0) for col in expected_cols]], columns=expected_cols)
        df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

        prob = model.predict_proba(df)[0][1]

        #Adjust on trusted domain
        if input_dict.get("is_safe_domain") == 1 and prob < 0.8:
            prob = max(0.0, prob - 0.4) #reduce phishing confidence

        pred = int(prob > 0.5)
        label = label_encoder.inverse_transform([pred])[0]
        return {"label": label, "probability": float(prob)}

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

@app.get("/")
def home():
    return {"message": "PhishDetector API is running"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
