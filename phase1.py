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