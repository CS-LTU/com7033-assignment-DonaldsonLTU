# data_loader.py
# I'm loading, cleaning, and inserting the stroke dataset into MongoDB securely

import pandas as pd
from pymongo import MongoClient

# I'm connecting to the same MongoDB as my main Flask app
client = MongoClient("mongodb://localhost:27017/")
db = client["secure_health_db"]
patients_collection = db["patients"]

# I'm loading the CSV dataset safely
df = pd.read_csv("Stroke prediction dataset.csv")

# I'm cleaning missing values
# - replacing missing BMI with the median
# - filling "Unknown" smoking status with "never smoked"
df["bmi"].fillna(df["bmi"].median(), inplace=True)
df["smoking_status"].replace("Unknown", "never smoked", inplace=True)

# I'm converting column names to lowercase for consistency
df.columns = [c.lower() for c in df.columns]

# I'm inserting cleaned records into MongoDB
patients_collection.delete_many({})  # clearing old data (safely)
patients_collection.insert_many(df.to_dict(orient="records"))

print(f"Inserted {patients_collection.count_documents({})} patient records successfully.")