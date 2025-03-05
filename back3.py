"""import sys
import io

# Ensure proper handling of special characters and emojis by setting UTF-8 encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
"""
import requests
import json
import time
from datetime import datetime
from django.core.management.base import BaseCommand
from threats.models import Threat
import re
import mysql.connector
import matplotlib.pyplot as plt

# Django Command Class
class Command(BaseCommand):
    help = "Runs the anomaly detection system and stores threats in the & run threat intelligence system"

    def handle(self, *args, **kwargs):
        # Simulated threat detection (replace this with your actual anomaly detection logic)
        detected_threats = [
            {"type": "Brute Force Attack", "severity": "high", "source_ip": "192.168.1.10"},
            {"type": "Phishing Attempt", "severity": "critical", "source_ip": "203.0.113.15"},
        ]

        for threat in detected_threats:
            Threat.objects.create(
                type=threat["type"],
                severity=threat["severity"],
                source_ip=threat["source_ip"],
                timestamp=datetime.now()
            )

        self.stdout.write(self.style.SUCCESS("Anomaly detection completed. Threats saved!"))

    def handel(self, *args, **kwargs):
        main()
        self.stdout.write(self.style.SUCCESS("Threat Intelligence System Completed!"))
    

# Phase 1 - Merged Code
# ---- fetching_logs.py ----
#step 1

import mysql.connector
import pandas as pd

myconn=mysql.connector.connect(host="localhost",user="root",password="#Pranay@0611",database="mysql")
cursor=myconn.cursor()

#creating a new databse to store logs if it doesn't exist
cursor.execute("CREATE DATABASE IF NOT EXISTS security_logs")

#creatinga table to store filtered logs
cursor.execute("USE security_logs")
cursor.execute("""CREATE TABLE IF NOT EXISTS filtered_logs(id INT AUTO_INCREMENT PRIMARY KEY,query TEXT,timestamp DATETIME)""")

#fetch only select ,update,delete , and insert queries 
cursor.execute("USE mysql")
cursor.execute(""" SELECT argument,event_time FROM general_log WHERE command_type='Query' AND (argument LIKE 'SELECT%' OR argument LIKE 'UPDATE%' OR argument LIKE 'DELETE%' OR argument LIKE 'INSERT%')""")
logs=cursor.fetchall()

#inserting filtered logs into the new table 
cursor.execute("USE security_logs")
for log in logs:
    cursor.execute("INSERT INTO filtered_logs(query,timestamp)VALUES (%s,%s)",log)
myconn.commit()

"""
#for deleteing the extra logs that is of long time  
cursor.execute("USE mysql")
cursor.execute("DELETE FROM general_log WHERE event_time < NOW() -INTERVAL 7 DAY")
myconn.commit()"""

cursor.close()
myconn.close()

print("logs have been successfully stored in the 'filtered_logs' table inside the 'security_logs' database.")


# ---- detected_logcsv.py ----
#step 3
import mysql.connector
import pandas as pd 
myconn=mysql.connector.connect(host="localhost",user="root",password="#Pranay@0611",database="security_logs")
cursor=myconn.cursor()
cursor.execute("select * from detected_threats")
detected_logs=cursor.fetchall()

if len(detected_logs)==0:
    print("NO THREAT DETECTED")
else:
    dataframe=pd.DataFrame(detected_logs,columns=["ID","Query","Timestamp","Threat Level","Reason"])
    report_filename="Threat_report.csv"
    dataframe.to_csv(report_filename,index=False)
    print("Threat reprot is generated successfully: %s" %report_filename)

cursor.close()
myconn.close()




#phase2
# Phase 2 - Merged Code
# ---- userbehaviorpattern_recongnization.py ----
import mysql.connector
import datetime

myconn=mysql.connector.connect(host="localhost",user="root",password="#Pranay@0611",database="security_logs")
cursor=myconn.cursor()

cursor.execute("CREATE TABLE IF NOT EXISTS user_behavior_profiles(id INT AUTO_INCREMENT PRIMARY KEY,user_host VARCHAR(200),average_login_time TIME,total_logins INT DEFAULT 0,last_login DATETIME)" )
myconn.commit()

cursor.execute("SELECT user_host,event_type,timestamp FROM user_access_logs WHERE event_type='Login' AND timestamp >=NOW() -INTERVAL 7 DAY")
logs=cursor.fetchall()

for log in logs:
    user_host,event_type,timestamp=log
    login_time=timestamp.time()

    cursor.execute("SELECT * FROM user_behavior_profiles WHERE user_host=%s",(user_host,))
    user_profile=cursor.fetchone()

    if user_profile:
        avg_login_time=user_profile[2]
        total_logins=user_profile[3]+1
        
        if avg_login_time is not None:
            avg_seconds=avg_login_time.total_seconds()
        else:
            avg_seconds=0  
        
        current_seconds=login_time.hour*3600+login_time.minute*60+login_time.second
        new_avg_seconds=(avg_seconds*(total_logins-1)+current_seconds)//total_logins
        new_avg_time=datetime.timedelta(seconds=new_avg_seconds)

        cursor.execute("UPDATE user_behavior_profiles SET average_login_time=%s, total_logins=%s,last_login=%s WHERE user_host=%s",(new_avg_time,total_logins,timestamp,user_host))

    else:
        cursor.execute("INSERT INTO user_behavior_profiles (user_host,average_login_time,total_logins,last_login)VALUES(%s,%s,%s,%s)",(user_host,login_time,1,timestamp))


myconn.commit()

cursor.close()
myconn.close()

print("USER BEHAVIOR PROFILES UPDATED SUCCESSFULLY!! ")

# ---- detecting_user_beh_pattern.py ----
#step3
#Detecting suspicious user behavior patterns 

import mysql.connector
import datetime

myconn=mysql.connector.connect(host="localhost",user="root",password="#Pranay@0611",database="security_logs")

cursor=myconn.cursor()

cursor.execute("CREATE TABLE IF NOT EXISTS suspicious_behavior(id INT AUTO_INCREMENT PRIMARY KEY,user_host VARCHAR(200),event_type VARCHAR(50),timestamp DATETIME,anomaly_type VARCHAR(100))")
myconn.commit()

cursor.execute("SELECT user_host,event_type,timestamp FROM user_access_logs WHERE timestamp >=NOW() -INTERVAL 1 DAY")
user_logs=cursor.fetchall()

for log in user_logs:
    user_host,event_type,timestamp=log
    cursor.execute("SELECT average_login_time,total_logins FROM user_behavior_profiles WHERE user_host=%s",(user_host,))
    profile=cursor.fetchone()
    if not profile:
        continue

    avg_login_time,total_logins=profile

    avg_seconds=avg_login_time.total_seconds()
    current_seconds=timestamp.hour*3600+timestamp.minute*60+timestamp.second
    time_difference=abs(avg_seconds-current_seconds)

    if time_difference>3600:
        cursor.execute("INSERT INTO suspicious_behavior(user_host,event_type,timestamp,anomaly_type)VALUES(%s,%s,%s,%s)",(user_host,event_type,timestamp,"UNUSUAL LOGIN TIME"))

    cursor.execute("SELECT COUNT(*) FROM user_access_logs WHERE user_host=%s AND timestamp >=%s -INTERVAL 10 MINUTE",(user_host,timestamp))
    login_count=cursor.fetchone()[0]

    if login_count>5:
        cursor.execute("INSERT INTO suspicious_behavior(user_host,event_type,timestamp,anomaly_type)VALUES(%s,%s,%s,%s)",(user_host,event_type,timestamp,"MULTIPLE RAPID LOGINS"))

myconn.commit()

cursor.close()
myconn.close()
print(" Suspicious user behavior has been logged successfully!!..")


#phase3
# Phase 3 - Merged Code
# ---- threat_classification_sys.py ----
#step 1

import re

def classify_threat(log):
    threat_rules={
        "Brute Froce Attack":r"failed login.*\b(attempts|retries)\b",
        "Phishing Attempt":r"phishing.*\b(link|email|url)\b",
        "Unusual Login location":r"login.*\b(location:unknown|foreign IP)\b",
        "DDoS Attack":r"(multiple requests|flood detected|traffic spike)",
        "Unauthorized Access":r"access denied.*\b(user: unknown|invalid)\b",
    }
    for threat,pattern in threat_rules.items():
        if re.search(pattern,log,re.IGNORECASE):
            return threat
        
    return "No threat Detected"

logs=["User failed login attempts from IP 192.168.1.10",
      "Phishing email with a malicious URL detected",
      "Login from location:unknown region",
      "Traffic spike detected-possible DDoS attack",
      "Access denied for user: unknown",
      "Normal user activity recorded"]

for log in logs:
    print(f"Log:{log}\n :: Threat:{classify_threat(log)}\n")

# ---- threat_prediction.py ----
# Step: Unusual Login Time Detection and Alert System

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

    print("Data Prepared Successfully!")
    print("Data Sample:\n", log_df.head())
    return X, y

def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("Model Training Completed!")
    print("Model Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    return model

def detect_anomalies(model):
    myconn = connect_db()
    cursor = myconn.cursor()

    cursor.execute("""SELECT user_host, event_type, suspicious, HOUR(timestamp), DAYOFWEEK(timestamp) 
                      FROM user_access_logs WHERE timestamp >= NOW() - INTERVAL 1 DAY""")
    new_logs = cursor.fetchall()

    print(f"Logs Fetched: {len(new_logs)} recent records.")
    for log in new_logs:
        user_host, event_type, suspicious, login_hour, day_of_week = log

        prediction = model.predict(np.array([[suspicious, login_hour, day_of_week]]))[0]

        print(f"Checking Log: {log} | Prediction: {prediction}")

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
    msg['Subject'] = "AI Threat Detection Alert"
    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(msg)
        server.quit()
        print("Email alert sent successfully!")
    except Exception as e:
        print(f" Failed to send email: {e}")

def send_discord_alert(message):
    discord_webhook_url = "https://discord.com/api/webhooks/1342550617213636628/a16XNcTb4TP-ovIZoP-ATHMfvf4IcQnj-O0TKEP3XcElN8cRKmiiNa6mpx-hOR_ObiWU"
    payload = {"content": f"**AI Threat Detection Alert**\n{message}"}

    response = requests.post(discord_webhook_url, json=payload)
    if response.status_code == 204:
        print("Discord alert sent successfully!")
    else:
        print(f" Failed to send Discord alert: {response.text}")

if __name__ == "__main__":
    logs = fetch_data()
    X, y = prepare_data(logs)
    model = train_model(X, y)
    detect_anomalies(model)
    print("All processes completed successfully!")


#phase4
# Phase 4 - Merged Code
# ---- def_automated_response.py ----
#phase 7
#step 2
import time
from phase3 import classify_threat

# Automated Response Function
def automated_response(threat_type):
    """
    Executes predefined actions based on the detected threat type.

    Parameters:
      threat_type (str): Classified threat type.

    Returns:
      str: Response action taken.
    """

    # Map threats to responses
    response_actions = {
        "Brute Force Attack": "Locking user account and alerting administrator.",
        "Phishing Attempt": "Quarantining suspicious email and notifying the user.",
        "Unusual Login Location": "Triggering multi-factor authentication (MFA).",
        "DDoS Attack": "Blocking suspicious IP and enabling traffic rate limits.",
        "Unauthorized Access": "Revoking user access and alerting the security team.",
    }

    # Execute the action
    action = response_actions.get(threat_type, "No action required. Normal activity detected.")

    print(f"Threat Detected: {threat_type}")
    print(f"Action: {action}")
    time.sleep(1)  # Simulate action delay
    return action

# Example Threats for Testing
detected_threats = [
    "Brute Force Attack",
    "Phishing Attempt",
    "Unusual Login Location",
    "DDoS Attack",
    "Unauthorized Access",
    "No Threat Detected"
]

# Trigger Responses
for threat in detected_threats:
    automated_response(threat)
    print("-" * 60)


#step 3
# Unified Threat Handling System
def threat_detection_and_response(log):
    """
    Detects the threat from the log and executes the appropriate response.

    Parameters:
      log (str): Input log describing system activity.

    Returns:
      str: Action performed.
    """
    threat = classify_threat(log)
    return automated_response(threat)

# Simulate Real-Time Logs
real_time_logs = [
    "User failed login attempts from IP 203.0.113.5",
    "Phishing attempt via suspicious link detected",
    "Unusual login location: foreign IP",
    "Traffic spike suggesting DDoS attack",
    "Access denied to unauthorized user",
    "Routine system check"
]

# Process Logs in Real-Time
for log in real_time_logs:
    print(f"Incoming Log: {log}")
    threat_detection_and_response(log)
    print("=" * 70)




# ---- automated_incident_reporting.py ----
import mysql.connector
import smtplib
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_mail_report(report_content):
    sender_email = "pgawande2005@gmail.com"
    receiver_email = "0808cb231043.ies@ipsacademy.org"
    password = "xbwr hsub sqow czkt"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = " Security Alert: Suspicious Activities Detected...!! "

    msg.attach(MIMEText(report_content, 'plain'))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(msg)
        server.quit()

        print("Incident report sent successfully via email!")

    except Exception as e:
        print(f" Error sending email: {e}")

def send_discord_alert(message_content):
    discord_webhook_url = "https://discord.com/api/webhooks/1342550617213636628/a16XNcTb4TP-ovIZoP-ATHMfvf4IcQnj-O0TKEP3XcElN8cRKmiiNa6mpx-hOR_ObiWU"

    # Discord message limit is 2000 characters, so split long messages
    chunks = [message_content[i:i + 1900] for i in range(0, len(message_content), 1900)]

    for chunk in chunks:
        message = {"content": f"{chunk}"}
        response = requests.post(discord_webhook_url, json=message)
        if response.status_code == 204:
            print("Discord alert sent successfully!")
        else:
            print(f"Failed to send Discord alert: {response.text}")

myconn = mysql.connector.connect(host="localhost", user="root", password="#Pranay@0611", database="security_logs")
cursor = myconn.cursor()

# Fetch suspicious logs from multiple tables
cursor.execute("""
    SELECT user_host, event_type, timestamp FROM user_access_logs WHERE suspicious = TRUE
               UNION
    SELECT query, threat_level, timestamp FROM detected_threats
    UNION
    SELECT user_host, anomaly_type, timestamp FROM anomaly_logs
    UNION
    SELECT user_host, anomaly_type, timestamp FROM location_anomalies
""")

suspicious_logs = cursor.fetchall()
cursor.close()
myconn.close()

if not suspicious_logs:
    print("No suspicious activities found.")
    exit()

# Create a combined report
report_content = " Incident Report - Detected Suspicious Activities \n\n"
discord_content = "** Security Alert: Suspicious Activities Detected! **\n\n"

for log in suspicious_logs:
    user, event_type, timestamp = log

    report_content += f"User/Query: {user}\n"
    report_content += f"Type/Threat Level: {event_type}\n"
    report_content += f"Timestamp: {timestamp}\n"
    report_content += "-" * 50 + "\n"

    discord_content += f"**User/Query:** {user}\n"
    discord_content += f"**Type/Threat Level:** {event_type}\n"
    discord_content += f"**Timestamp:** {timestamp}\n"
    discord_content += "\n"

# Send alerts
send_mail_report(report_content)
send_discord_alert(discord_content)

print(" All anomaly alerts sent successfully!")




#phase5
# Phase 5 - Merged Code
# ---- response_execution.py ----
#phase 7 
#step 3
# Unified Threat Handlin
from  phase4 import automated_response
from phase3 import classify_threat


def threat_detection_and_response(log):
    """
    Detects the threat from the log and executes the appropriate response.

    Parameters:
      log (str): Input log describing system activity.

    Returns:
      str: Action performed.
    """
    threat = classify_threat(log)
    return automated_response(threat)

# Simulate Real-Time Logs
real_time_logs = [
    "User failed login attempts from IP 203.0.113.5",
    "Phishing attempt via suspicious link detected",
    "Unusual login location: foreign IP",
    "Traffic spike suggesting DDoS attack",
    "Access denied to unauthorized user",
    "Routine system check"
]

# Process Logs in Real-Time
for log in real_time_logs:
    print(f" Incoming Log: {log}")
    threat_detection_and_response(log)
    print("=" * 70)





#phase6
# Phase 6 - Merged Code
# ---- rreal_time_alertandlogginsys.py ----
#phase 7
#step4
import logging
import time

# Configure Logging System (Stores logs in a file)
logging.basicConfig(
    filename="threat_log.txt",
    level=logging.INFO,
    format="%(asctime)s - [THREAT: %(message)s]",
    datefmt="%Y-%m-%d %H:%M:%S"
    )

# Alert System (Simulate sending an alert)
def send_alert(threat_type, action):
    """
    Sends an alert for critical threats.

    Parameters:
      threat_type (str): Type of detected threat.
      action (str): Automated action taken.
    """
    alert_message = f"ALERT: {threat_type} detected! Action Taken: {action}"
    print(alert_message)  # Simulate alert notification
    # Extend here to send email, SMS, or push notification
    return alert_message

# Automated Response System (Enhanced with Logging and Alerts)
def automated_response_with_logging(threat_type):
    """
    Executes automated actions, logs the event, and sends alerts for critical threats.

    Parameters:
      threat_type (str): Classified threat type.

    Returns:
      str: Response action taken.
    """
    # Define Automated Responses
    response_actions = {
        "Brute Force Attack": "Locking user account and alerting administrator.",
        "Phishing Attempt": "Quarantining suspicious email and notifying the user.",
        "Unusual Login Location": "Triggering multi-factor authentication (MFA).",
        "DDoS Attack": "Blocking suspicious IP and enabling traffic rate limits.",
        "Unauthorized Access": "Revoking user access and alerting the security team.",
    }

    # Identify action or fallback to default
    action = response_actions.get(threat_type, "No action required. Normal activity detected.")

    # Log and alert only if a serious threat is detected
    if threat_type in response_actions:
        logging.info(f"{threat_type} | Action: {action}")
        send_alert(threat_type, action)

    # Output Response
    print(f"Threat Detected: {threat_type}")
    print(f"Action: {action}")
    time.sleep(1)  # Simulate action delay

    return action

# Simulate Real-Time Threat Detection
detected_threats = [
    "Brute Force Attack",
    "Phishing Attempt",
    "Unusual Login Location",
    "DDoS Attack",
    "Unauthorized Access",
    "No Threat Detected"
]

# Process and Log Each Threat in Real-Time
for threat in detected_threats:
    automated_response_with_logging(threat)
    print("-" * 70)

print("\nAll threats processed. Check 'threat_log.txt' for detailed logs.")



# ---- notify_detectedthreats.py ----
#step 4
import requests
discord_webhook_url="https://discord.com/api/webhooks/1342550617213636628/a16XNcTb4TP-ovIZoP-ATHMfvf4IcQnj-O0TKEP3XcElN8cRKmiiNa6mpx-hOR_ObiWU"

def send_discord_alert(query,threat_level,reason,timestamp):
    message={"content":f"**Security Alert!!!!**\n\n"
            f"**Query : **'{query}'\n"
            f"**Threat_level:** {threat_level}\n"
            f"**Reason:** {reason}\n"
            f"**Timestamp:** {timestamp}\n\n"
            f"***** Immediate Action Requiredd!!!! *****\n"
        }
    response=requests.post(discord_webhook_url,json=message)
    if response.status_code==204:
        print("**Discord alert sent successfully!**")
    else:
        print(f"Falied to send discord alert : {response.text}")







#phase7import mysql.connector
import mysql.connector
import matplotlib.pyplot as plt
import re
from datetime import datetime
import requests
from django.core.management.base import BaseCommand
from threats.models import Threat
from transformers import pipeline
from phase6 import send_alert
import tf_keras as keras
classifier=pipeline('sentiment-analysis',model='distilbert-base-uncased-finetuned-sst-2-english')
# Django Command Class
class Command(BaseCommand):
    help = "Runs the anomaly detection system and stores threats in the & run threat intelligence system"

    def handle(self, *args, **kwargs):
        # Simulated threat detection (replace this with your actual anomaly detection logic)
        detected_threats = [
            {"type": "Brute Force Attack", "severity": "high", "source_ip": "192.168.1.10"},
            {"type": "Phishing Attempt", "severity": "critical", "source_ip": "203.0.113.15"},
        ]

        for threat in detected_threats:
            Threat.objects.create(
                type=threat["type"],
                severity=threat["severity"],
                source_ip=threat["source_ip"],
                timestamp=datetime.now()
            )

        self.stdout.write(self.style.SUCCESS("Anomaly detection completed. Threats saved!"))

        # Run the threat intelligence system
        main()
        self.stdout.write(self.style.SUCCESS("Threat Intelligence System Completed!"))

        # Call Phase 7 functions
        visualize_threats()
        handle_user_access_logs()

# Phase 7: Visualizing Threats
def visualize_threats():
    try:
        # Database connection
        myconn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="#Pranay@0611",
            database="security_logs"
        )
        cursor = myconn.cursor()

        # Fetching data from the detected_threats table
        cursor.execute("SELECT threat_level, COUNT(*) FROM detected_threats GROUP BY threat_level")
        threat_data = cursor.fetchall()

        # Close the cursor and connection
        cursor.close()
        myconn.close()

        # Print raw data for debugging
        print("Fetched Threat Data:", threat_data)

        # Ensure all threat levels (LOW, MEDIUM, HIGH) are accounted for
        all_levels = ['LOW', 'MEDIUM', 'HIGH']
        counts_dict = {level: 0 for level in all_levels}

        # Update counts based on fetched data
        for level, count in threat_data:
            counts_dict[level.upper()] = count

        # Extracting levels and counts in the correct order
        threat_levels = list(counts_dict.keys())
        threat_counts = list(counts_dict.values())

        # Debug print to verify final count distribution
        print("Threat Levels:", threat_levels)
        print("Threat Counts:", threat_counts)

        # Create a bar chart
        plt.figure(figsize=(8, 6))
        plt.bar(threat_levels, threat_counts, color=['green', 'orange', 'red'])
        plt.xlabel("Threat Level")
        plt.ylabel("Count")
        plt.title("Threat Level Distribution")

        # Save and display the chart
        plt.savefig("threat_level_distribution.png")
        plt.show()

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    except Exception as e:
        print(f"Unexpected error: {e}")

# Phase 7: Handling User Access Logs
# Create filter_general_log table
def create_filter_general_log_table():
    myconn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="#Pranay@0611",
        database="security_logs"
    )
    cursor = myconn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS filter_general_log (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_host VARCHAR(255),
            argument TEXT,
            event_time DATETIME
        )
    """)
    myconn.commit()
    cursor.close()
    myconn.close()
    print("✅ filter_general_log Table Ready")
def fetch_and_store_recent_logs():
    myconn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="#Pranay@0611",
        database="mysql"
    )
    cursor = myconn.cursor()
    cursor.execute("""
        SELECT user_host, argument, event_time 
        FROM general_log 
        WHERE command_type ='Connect' 
        ORDER BY event_time DESC 
        LIMIT 100
    """)
    recent_logs = cursor.fetchall()

    cursor.execute("USE security_logs")
    for log in recent_logs:
        cursor.execute("INSERT INTO filter_general_log(user_host, argument, event_time) VALUES (%s, %s, %s)", log)
    myconn.commit()
    cursor.close()
    myconn.close()
    print("✅ Recent logs fetched and stored in filter_general_log")
# Fetch recent 100 logs from general_log and store in filter_general_log
def fetch_and_store_recent_logs():
    myconn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="#Pranay@0611",
        database="mysql"
    )
    cursor = myconn.cursor()
    cursor.execute("""
        SELECT user_host, argument, event_time 
        FROM general_log 
        WHERE command_type ='Connect' 
        ORDER BY event_time DESC 
        LIMIT 100
    """)
    recent_logs = cursor.fetchall()

    cursor.execute("USE security_logs")
    for log in recent_logs:
        cursor.execute("INSERT INTO filter_general_log(user_host, argument, event_time) VALUES (%s, %s, %s)", log)
    myconn.commit()
    cursor.close()
    myconn.close()
    print("✅ Recent logs fetched and stored in filter_general_log")
def handle_user_access_logs():
    try:
        myconn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="#Pranay@0611",
            database="security_logs"
        )
        cursor = myconn.cursor()

        cursor.execute("CREATE TABLE IF NOT EXISTS user_access_logs(id INT AUTO_INCREMENT PRIMARY KEY, user_host VARCHAR(255), event_type VARCHAR(50), timestamp DATETIME, suspicious BOOLEAN)")
        myconn.commit()

        # Fetch recent logs from filter_general_log instead of general_log
        cursor.execute("SELECT user_host, argument, event_time FROM filter_general_log")
        user_logs = cursor.fetchall()

        suspicious_pattern = [r"unknown user", r"Access denied"]

        for log in user_logs:
            user_host, argument, event_time = log

            if isinstance(argument, bytes):
                argument = argument.decode('utf-8', errors='ignore')

            if argument is None:
                argument = ""

            if "Connect" in argument:
                event_type = "Login"
            else:
                event_type = "Logout"

            suspicious = any(re.search(pattern, argument, re.IGNORECASE) for pattern in suspicious_pattern)

            cursor.execute("INSERT INTO user_access_logs(user_host, event_type, timestamp, suspicious) VALUES (%s, %s, %s, %s)", (user_host, event_type, event_time, suspicious))

        myconn.commit()

        cursor.close()
        myconn.close()
        print("User access logs have been successfully stored in the 'user_access_logs' table")

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    except Exception as e:
        print(f"Unexpected error: {e}")
# Phase 8: Threat Intelligence Integration

# Connect to MySQL Database
def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="#Pranay@0611",
        database="security_logs"
    )

# Create threat_intelligence_logs table (if not exists)
def create_table():
    db = connect_db()
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intelligence_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            source VARCHAR(255),
            threat_type VARCHAR(100),
            threat_data TEXT,
            detected_at DATETIME
        )
    ''')
    db.commit()
    cursor.close()
    db.close()
    print("✅ Threat Intelligence Table Ready")

# Fetch threat intelligence from external APIs
def fetch_threat_intelligence():
    feeds = {
        "Malicious IPs": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "Phishing Domains": "https://phish.sinking.yachts/v2/all.json"
    }

    threat_data = []

    for source, url in feeds.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Data fetched from {source}")

                if source == "Malicious IPs":
                    for entry in data.get('data', []):
                        threat_data.append(("Malicious IP", entry['ip_address'], source))

                elif source == "Phishing Domains":
                    for domain in data:
                        threat_data.append(("Phishing Domain", domain, source))

            else:
                print(f"❌ Failed to fetch data from {source}")
        except Exception as e:
            print(f"❌ Error fetching from {source}: {e}")
    print(f"Threat data collected: {threat_data}")
    return threat_data

# Store threat intelligence in the database
def store_threat_data(threat_data):
    db = connect_db()
    cursor = db.cursor()

    for threat_type, threat_info, source in threat_data:
        print(f"Storing: {threat_type}, {threat_info}, {source}")
        sql_query = '''
            INSERT INTO threat_intelligence_logs (source, threat_type, threat_data, detected_at)
            VALUES (%s, %s, %s, NOW())
        '''
        try:
            cursor.execute(sql_query, (source, threat_type, threat_info))
            db.commit()
        except Exception as e:
            print(f"Error storing data: {e}")

    print(f"✅ Stored {len(threat_data)} threat records.")
    cursor.close()
    db.close()

# Compare detected logs with external threat intelligence
def check_for_matches():
    db = connect_db()
    cursor = db.cursor()

    # Fetch recent detected logs
    cursor.execute("SELECT user_host, argument, event_time FROM filter_general_log WHERE event_time >= NOW() - INTERVAL 1 DAY")
    logs = cursor.fetchall()

    # Fetch threat intelligence data
    cursor.execute("SELECT threat_data FROM threat_intelligence_logs")
    threat_entries = [row[0] for row in cursor.fetchall()]

    matches = []
    for log in logs:
        user_host, argument, event_time = log
        if user_host in threat_entries:
            matches.append((user_host, argument, event_time))

    if matches:
        print("🚨 MATCHES FOUND! Possible Threat Detected:")
        for match in matches:
            print(f"User: {match[1]}, IP: {match[2]}")
            # You could trigger alerts here (email, Discord, etc.)

    else:
        print("✅ No matches found.")

    cursor.close()
    db.close()
# Main function to run the integration
def main():
    create_table()
    print("DATABASE CHECK COMPLETED!!")  # Ensure the table is ready
    threat_data = fetch_threat_intelligence()
    if threat_data:
        print(f"Fetched {len(threat_data)} threat records.")
        store_threat_data(threat_data)
        check_for_matches()  # Cross-check against internal logs
    else:
        print("❌ No threat data fetched. Check the sources or try again later.")
    print("🎯 Advanced Threat Intelligence Process Completed!")

if __name__ == "__main__":
    main()
"""
#phase7
# Phase 7 - Merged Code
import mysql.connector
import matplotlib.pyplot as plt
import re
from datetime import datetime
import requests
from django.core.management.base import BaseCommand
from threats.models import Threat

# Django Command Class
class Command(BaseCommand):
    help = "Runs the anomaly detection system and stores threats in the & run threat intelligence system"

    def handle(self, *args, **kwargs):
        # Simulated threat detection (replace this with your actual anomaly detection logic)
        detected_threats = [
            {"type": "Brute Force Attack", "severity": "high", "source_ip": "192.168.1.10"},
            {"type": "Phishing Attempt", "severity": "critical", "source_ip": "203.0.113.15"},
        ]

        for threat in detected_threats:
            Threat.objects.create(
                type=threat["type"],
                severity=threat["severity"],
                source_ip=threat["source_ip"],
                timestamp=datetime.now()
            )

        self.stdout.write(self.style.SUCCESS("Anomaly detection completed. Threats saved!"))

        # Run the threat intelligence system
        main()
        self.stdout.write(self.style.SUCCESS("Threat Intelligence System Completed!"))

#visualizing threats
def visualize_threats():
    try:
        # Database connection
        myconn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="#Pranay@0611",
            database="security_logs"
        )
        cursor = myconn.cursor()

        # Fetching data from the detected_threats table
        cursor.execute("SELECT threat_level, COUNT(*) FROM detected_threats GROUP BY threat_level")
        threat_data = cursor.fetchall()

        # Close the cursor and connection
        cursor.close()
        myconn.close()

        # Print raw data for debugging
        print("Fetched Threat Data:", threat_data)

        # Ensure all threat levels (LOW, MEDIUM, HIGH) are accounted for
        all_levels = ['LOW', 'MEDIUM', 'HIGH']
        counts_dict = {level: 0 for level in all_levels}

        # Update counts based on fetched data
        for level, count in threat_data:
            counts_dict[level.upper()] = count

        # Extracting levels and counts in the correct order
        threat_levels = list(counts_dict.keys())
        threat_counts = list(counts_dict.values())

        # Debug print to verify final count distribution
        print("Threat Levels:", threat_levels)
        print("Threat Counts:", threat_counts)

        # Create a bar chart
        plt.figure(figsize=(8, 6))
        plt.bar(threat_levels, threat_counts, color=['green', 'orange', 'red'])
        plt.xlabel("Threat Level")
        plt.ylabel("Count")
        plt.title("Threat Level Distribution")

        # Save and display the chart
        plt.savefig("threat_level_distribution.png")
        plt.show()

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    except Exception as e:
        print(f"Unexpected error: {e}")
#user_access_logs
def handle_user_access_logs():
    try:
        myconn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="#Pranay@0611",
            database="security_logs"
        )
        cursor = myconn.cursor()

        cursor.execute("CREATE TABLE IF NOT EXISTS user_access_logs(id INT AUTO_INCREMENT PRIMARY KEY, user_host VARCHAR(255), event_type VARCHAR(50), timestamp DATETIME, suspicious BOOLEAN)")
        myconn.commit()

        cursor.execute("USE mysql")
        cursor.execute("SELECT user_host, argument, event_time FROM general_log WHERE command_type ='Connect'")
        user_logs = cursor.fetchall()

        cursor.execute("USE security_logs")
        suspicious_pattern = [r"unknown user", r"Access denied"]

        for log in user_logs:
            user_host, argument, event_time = log

            if isinstance(argument, bytes):
                argument = argument.decode('utf-8', errors='ignore')

            if argument is None:
                argument = ""

            if "Connect" in argument:
                event_type = "Login"
            else:
                event_type = "Logout"

            suspicious = any(re.search(pattern, argument, re.IGNORECASE) for pattern in suspicious_pattern)

            cursor.execute("INSERT INTO user_access_logs(user_host, event_type, timestamp, suspicious) VALUES (%s, %s, %s, %s)", (user_host, event_type, event_time, suspicious))

        myconn.commit()

        cursor.close()
        myconn.close()
        print("User access logs have been successfully stored in the 'user_access_logs' table")

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    except Exception as e:
        print(f"Unexpected error: {e}")

"""

"""
#phase7
import mysql.connector
import matplotlib.pyplot as plt
import re
from datetime import datetime
import requests
from django.core.management.base import BaseCommand
from threats.models import Threat

# Django Command Class
class Command(BaseCommand):
    help = "Runs the anomaly detection system and stores threats in the & run threat intelligence system"

    def handle(self, *args, **kwargs):
        # Simulated threat detection (replace this with your actual anomaly detection logic)
        detected_threats = [
            {"type": "Brute Force Attack", "severity": "high", "source_ip": "192.168.1.10"},
            {"type": "Phishing Attempt", "severity": "critical", "source_ip": "203.0.113.15"},
        ]

        for threat in detected_threats:
            Threat.objects.create(
                type=threat["type"],
                severity=threat["severity"],
                source_ip=threat["source_ip"],
                timestamp=datetime.now()
            )

        self.stdout.write(self.style.SUCCESS("Anomaly detection completed. Threats saved!"))

        # Run the threat intelligence system
        main()
        self.stdout.write(self.style.SUCCESS("Threat Intelligence System Completed!"))
        visualize_threats()
        handle_user_access_logs()
# Phase 7: Visualizing Threats
def visualize_threats():
    try:
        # Database connection
        myconn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="#Pranay@0611",
            database="security_logs"
        )
        cursor = myconn.cursor()

        # Fetching data from the detected_threats table
        cursor.execute("SELECT threat_level, COUNT(*) FROM detected_threats GROUP BY threat_level")
        threat_data = cursor.fetchall()

        # Close the cursor and connection
        cursor.close()
        myconn.close()

        # Print raw data for debugging
        print("Fetched Threat Data:", threat_data)

        # Ensure all threat levels (LOW, MEDIUM, HIGH) are accounted for
        all_levels = ['LOW', 'MEDIUM', 'HIGH']
        counts_dict = {level: 0 for level in all_levels}

        # Update counts based on fetched data
        for level, count in threat_data:
            counts_dict[level.upper()] = count

        # Extracting levels and counts in the correct order
        threat_levels = list(counts_dict.keys())
        threat_counts = list(counts_dict.values())

        # Debug print to verify final count distribution
        print("Threat Levels:", threat_levels)
        print("Threat Counts:", threat_counts)

        # Create a bar chart
        plt.figure(figsize=(8, 6))
        plt.bar(threat_levels, threat_counts, color=['green', 'orange', 'red'])
        plt.xlabel("Threat Level")
        plt.ylabel("Count")
        plt.title("Threat Level Distribution")

        # Save and display the chart
        plt.savefig("threat_level_distribution.png")
        plt.show()

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    except Exception as e:
        print(f"Unexpected error: {e}")

# Phase 7: Handling User Access Logs
def handle_user_access_logs():
    try:
        myconn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="#Pranay@0611",
            database="security_logs"
        )
        cursor = myconn.cursor()

        cursor.execute("CREATE TABLE IF NOT EXISTS user_access_logs(id INT AUTO_INCREMENT PRIMARY KEY, user_host VARCHAR(255), event_type VARCHAR(50), timestamp DATETIME, suspicious BOOLEAN)")
        myconn.commit()

        cursor.execute("USE mysql")
        cursor.execute("SELECT user_host, argument, event_time FROM general_log WHERE command_type ='Connect'")
        user_logs = cursor.fetchall()

        cursor.execute("USE security_logs")
        suspicious_pattern = [r"unknown user", r"Access denied"]

        for log in user_logs:
            user_host, argument, event_time = log

            if isinstance(argument, bytes):
                argument = argument.decode('utf-8', errors='ignore')

            if argument is None:
                argument = ""

            if "Connect" in argument:
                event_type = "Login"
            else:
                event_type = "Logout"

            suspicious = any(re.search(pattern, argument, re.IGNORECASE) for pattern in suspicious_pattern)

            cursor.execute("INSERT INTO user_access_logs(user_host, event_type, timestamp, suspicious) VALUES (%s, %s, %s, %s)", (user_host, event_type, event_time, suspicious))

        myconn.commit()

        cursor.close()
        myconn.close()
        print("User access logs have been successfully stored in the 'user_access_logs' table")

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    except Exception as e:
        print(f"Unexpected error: {e}")


# phase8
# Phase 8 - Merged Code
# ---- threat_intelligence_sys.py ----  
import mysql.connector
import requests
import json
import time
from datetime import datetime
from django.core.management.base import BaseCommand
from threats.models import Threat

# Django Command Class
class Command(BaseCommand):
    help = "Runs the anomaly detection system and stores threats in the & run threat intelligence system"

    def handle(self, *args, **kwargs):
        # Simulated threat detection (replace this with your actual anomaly detection logic)
        detected_threats = [
            {"type": "Brute Force Attack", "severity": "high", "source_ip": "192.168.1.10"},
            {"type": "Phishing Attempt", "severity": "critical", "source_ip": "203.0.113.15"},
        ]

        for threat in detected_threats:
            Threat.objects.create(
                type=threat["type"],
                severity=threat["severity"],
                source_ip=threat["source_ip"],
                timestamp=datetime.now()
            )

        self.stdout.write(self.style.SUCCESS("Anomaly detection completed. Threats saved!"))

        # Run the threat intelligence system
        main()
        self.stdout.write(self.style.SUCCESS("Threat Intelligence System Completed!"))

# Phase 8: Threat Intelligence Integration

# Connect to MySQL Database
def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="#Pranay@0611",
        database="security_logs"
    )

# Create threat_intelligence_logs table (if not exists)
def create_table():
    db = connect_db()
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intelligence_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            source VARCHAR(255),
            threat_type VARCHAR(100),
            threat_data TEXT,
            detected_at DATETIME
        )
    ''')
    db.commit()
    cursor.close()
    db.close()
    print("✅ Threat Intelligence Table Ready")

# Fetch threat intelligence from external APIs
def fetch_threat_intelligence():
    feeds = {
        "Malicious IPs": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "Phishing Domains": "https://phish.sinking.yachts/v2/all.json"
    }

    threat_data = []

    for source, url in feeds.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Data fetched from {source}")

                if source == "Malicious IPs":
                    for entry in data.get('data', []):
                        threat_data.append(("Malicious IP", entry['ip_address'], source))

                elif source == "Phishing Domains":
                    for domain in data:
                        threat_data.append(("Phishing Domain", domain, source))

            else:
                print(f"❌ Failed to fetch data from {source}")
        except Exception as e:
            print(f"❌ Error fetching from {source}: {e}")
    print(f"Threat data collected: {threat_data}")
    return threat_data

# Store threat intelligence in the database
def store_threat_data(threat_data):
    db = connect_db()
    cursor = db.cursor()

    for threat_type, threat_info, source in threat_data:
        print(f"Storing: {threat_type}, {threat_info}, {source}")
        sql_query = '''
            INSERT INTO threat_intelligence_logs (source, threat_type, threat_data, detected_at)
            VALUES (%s, %s, %s, NOW())
        '''
        try:
            cursor.execute(sql_query, (source, threat_type, threat_info))
            db.commit()
        except Exception as e:
            print(f"Error storing data: {e}")

    print(f"✅ Stored {len(threat_data)} threat records.")
    cursor.close()
    db.close()

# Compare detected logs with external threat intelligence
def check_for_matches():
    db = connect_db()
    cursor = db.cursor()

    # Fetch recent detected logs
    cursor.execute("SELECT id, user_id, ip_address FROM filtered_logs WHERE detected_at >= NOW() - INTERVAL 1 DAY")
    logs = cursor.fetchall()

    # Fetch threat intelligence data
    cursor.execute("SELECT threat_data FROM threat_intelligence_logs")
    threat_entries = [row[0] for row in cursor.fetchall()]

    matches = []
    for log in logs:
        log_id, user_id, ip_address = log
        if ip_address in threat_entries:
            matches.append((log_id, user_id, ip_address))

    if matches:
        print("🚨 MATCHES FOUND! Possible Threat Detected:")
        for match in matches:
            print(f"User: {match[1]}, IP: {match[2]}")
            # You could trigger alerts here (email, Discord, etc.)

    else:
        print("✅ No matches found.")

    cursor.close()
    db.close()

# Main function to run the integration
def main():
    create_table()
    print("DATABASE CHECK COMPLETED!!")  # Ensure the table is ready
    threat_data = fetch_threat_intelligence()
    if threat_data:
        print(f"Fetched {len(threat_data)} threat records.")
        store_threat_data(threat_data)
        check_for_matches()  # Cross-check against internal logs
    else:
        print("❌ No threat data fetched. Check the sources or try again later.")
    print("🎯 Advanced Threat Intelligence Process Completed!")

if __name__ == "__main__":
    main()
"""