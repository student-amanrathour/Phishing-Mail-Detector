import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump

# 1️⃣ Load dataset
df = pd.read_csv("data/dataset_phishing.csv")

# 2️⃣ Convert labels to numeric
label_encoder = LabelEncoder()
df['status'] = label_encoder.fit_transform(df['status'])  # phishing=1, legitimate=0
print("Label mapping:", dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_))))

# 3️⃣ Drop non-feature columns (like URL itself)
X = df.drop(columns=['url', 'status'])
y = df['status']

# 4️⃣ Split train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5️⃣ Train a Random Forest model
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# 6️⃣ Evaluate
y_pred = model.predict(X_test)
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# 7️⃣ Save model and label encoder
dump(model, "model/phish_feature_model.joblib")
dump(label_encoder, "model/label_encoder.joblib")
print("Model saved as phish_feature_model.joblib")

