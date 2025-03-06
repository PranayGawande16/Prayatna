# Phase 3 - Merged Code
#step 1
from transformers import pipeline

# Load the pre-trained model and tokenizer
classifier = pipeline('sentiment-analysis', model='distilbert-base-uncased-finetuned-sst-2-english')

def classify_threat(log):
    # Use the Hugging Face classifier to predict the sentiment of the log entry
    result = classifier(log)[0]
    label = result['label']
    score = result['score']

    # Map the sentiment label to a threat type
    if label == 'NEGATIVE' and score > 0.9:
        return "Potential Threat Detected"
    else:
        return "No Threat Detected"

# Example Threats for Testing
logs = [
    "User failed login attempts from IP 192.168.1.10",
    "Phishing email with a malicious URL detected",
    "Login from location: unknown region",
    "Traffic spike detected - possible DDoS attack",
    "Access denied for user: unknown",
    "Normal user activity recorded"
]

for log in logs:
    print(f"Log: {log}\n :: Threat: {classify_threat(log)}\n")





    
# ---- threat_prediction.py ----
# Step 5 of Phase 6: Unusual Login Time Detection and Alert System

import mysql.connector
import pandas as pd
import numpy as np
import smtplib
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

def connect_db():
    return mysql.connector.connect(host="localhost", user="root", password="#Pranay@0611", database="security_logs")

def fetch_data():
    myconn = connect_db()
    cursor = myconn.cursor()
    cursor.execute("""SELECT user_host, event_type, suspicious, HOUR(timestamp) AS login_hour, 
                      DAYOFWEEK(timestamp) AS day_of_week FROM user_access_logs""")
    logs = cursor.fetchall()
    myconn.close()
    return logs

def prepare_data(logs):
    log_df = pd.DataFrame(logs, columns=['user_host', 'event_type', 'suspicious', 'login_hour', 'day_of_week'])

    # Handle missing values and convert data types
    log_df['suspicious'] = log_df['suspicious'].fillna(0).astype(int)

    # Prepare features (X) and target (y)
    X = log_df[['suspicious', 'login_hour', 'day_of_week']]
    y = (log_df['login_hour'].apply(lambda x: 1 if x < 6 or x > 22 else 0))

    print("✅ Data Prepared Successfully!")
    print("📊 Data Sample:\n", log_df.head())
    return X, y

def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("✅ Model Training Completed!")
    print("📈 Model Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    return model

def detect_anomalies(model):
    myconn = connect_db()
    cursor = myconn.cursor()

    cursor.execute("""SELECT user_host, event_type, suspicious, HOUR(timestamp), DAYOFWEEK(timestamp) 
                      FROM user_access_logs WHERE timestamp >= NOW() - INTERVAL 1 DAY""")
    new_logs = cursor.fetchall()

    print(f"✅ Logs Fetched: {len(new_logs)} recent records.")

    for log in new_logs:
        user_host, event_type, suspicious, login_hour, day_of_week = log

        prediction = model.predict(np.array([[suspicious, login_hour, day_of_week]]))[0]

        print(f"🧐 Checking Log: {log} | Prediction: {prediction}")

        if prediction == 1:
            anomaly_type = "Unusual Login Time Detected"
            cursor.execute("""INSERT INTO anomaly_logs (user_host, event_type, timestamp, anomaly_type) 
                              VALUES (%s, %s, NOW(), %s)""", (user_host, event_type, anomaly_type))
            myconn.commit()

            alert_message = f"User: {user_host}\nEvent: {event_type}\nAnomaly: {anomaly_type}\n"

            send_email_alert(alert_message)
            send_discord_alert(alert_message)

    cursor.close()
    myconn.close()

def send_email_alert(message):
    sender_email = "pgawande2005@gmail.com"
    receiver_email = "0808cb231043.ies@ipsacademy.org"
    password = "xbwr hsub sqow czkt"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "🚨 AI Threat Detection Alert"
    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(msg)
        server.quit()
        print("✅ Email alert sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def send_discord_alert(message):
    discord_webhook_url = "https://discord.com/api/webhooks/1342550617213636628/a16XNcTb4TP-ovIZoP-ATHMfvf4IcQnj-O0TKEP3XcElN8cRKmiiNa6mpx-hOR_ObiWU"
    payload = {"content": f"*AI Threat Detection Alert*\n{message}"}

    response = requests.post(discord_webhook_url, json=payload)
    if response.status_code == 204:
        print("✅ Discord alert sent successfully!")
    else:
        print(f"❌ Failed to send Discord alert: {response.text}")

if _name_ == "_main_":
    logs = fetch_data()
    X, y = prepare_data(logs)
    model = train_model(X, y)
    detect_anomalies(model)
    print("🎉 All processes completed successfully!")