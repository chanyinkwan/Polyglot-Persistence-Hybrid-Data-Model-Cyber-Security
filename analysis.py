import sqlite3
import pymongo
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

# =========================================================================
#  FULL SECURITY ANALYSIS SUITE
#  -----------------------------------------------------------------------
#  Purpose: Executes 8 distinct security checks across SQL and NoSQL data.
#  Usage: Run this script after 'setup_all_databases.py'.
# =========================================================================

# CONFIGURATION
SQLITE_DB = 'security_db.db'
MONGO_URI = 'mongodb://localhost:27017/'
MONGO_DB = 'Cybersecurity_Dep'

print("=======================================================")
print(f"   SECURITY OPERATIONS CENTER (SOC) REPORT")
print(f"   Date: {datetime.now().strftime('%Y-%m-%d')}")
print("=======================================================\n")

# --- CONNECTIONS ---
try:
    sql_conn = sqlite3.connect(SQLITE_DB)
    mongo_client = pymongo.MongoClient(MONGO_URI)
    mongo_db = mongo_client[MONGO_DB]
    print("[SYSTEM] Databases Connected Successfully.\n")
except Exception as e:
    print(f"[CRITICAL] Connection failed: {e}")
    exit()

# =========================================================================
#  SECTION 1: BASELINE SECURITY (Standard Hygiene)
# =========================================================================
print("--- SECTION 1: BASELINE SECURITY MONITORING ---")

# 1. INSIDER THREAT (Time-Based)
# ---------------------------------------------
print("\n[Use Case 1] Insider Threat Detection (Access outside 08:00-20:00)")
query_insider = """
SELECT 
    e.first_name || ' ' || e.last_name AS Employee,
    e.Department,
    f.timestamp AS Access_Time
FROM File_Access f
JOIN Employee_Data e ON f.employee_id = e.employee_id
WHERE strftime('%H', f.timestamp) < '08' OR strftime('%H', f.timestamp) >= '20'
"""
try:
    df_insider = pd.read_sql_query(query_insider, sql_conn)
    if not df_insider.empty:
        print(df_insider.to_string(index=False))
    else:
        print(">> No after-hours access detected.")
except Exception as e: print(f"Error: {e}")

# 2. SLA KPI (Incident Response)
# ---------------------------------------------
print("\n[Use Case 2] SLA Performance KPIs (Avg Response Time)")
query_sla = """
SELECT 
    i.incident_type,
    AVG((julianday(r.response_end_time) - julianday(r.response_start_time)) * 1440) AS Avg_Minutes
FROM Incident_Response r
JOIN Security_Incidents i ON r.incident_id = i.incident_id
GROUP BY i.incident_type
"""
try:
    df_sla = pd.read_sql_query(query_sla, sql_conn)
    print(df_sla.to_string(index=False))
except Exception as e: print(f"Error: {e}")

# 3. IDENTITY RISKS (NoSQL Aggregation)
# ---------------------------------------------
print("\n[Use Case 3] Identity Risks (Repeated Failed Logins)")
pipeline = [
    {"$match": {"STATUS": "Failed"}},
    {"$group": {"_id": "$_ID", "Failed_Count": {"$sum": 1}}},
    {"$match": {"Failed_Count": {"$gte": 2}}},
    {"$sort": {"Failed_Count": -1}}
]
try:
    results = list(mongo_db["Access_logs"].aggregate(pipeline))
    if results:
        df_identity = pd.DataFrame(results)
        print(df_identity.to_string(index=False))
    else:
        print(">> No users exceeded failure threshold.")
except Exception as e: print(f"Error: {e}")

# 4. PHISHING VULNERABILITY (NoSQL Query)
# ---------------------------------------------
print("\n[Use Case 4] Phishing Victims (High Risk Clicks)")
query_phish = {"ANOMALY_SCORE": {"$gt": 0.8}, "LINK_CLICKED": True}
try:
    victim_count = mongo_db["Phishing_attacks"].count_documents(query_phish)
    print(f">> Total Users Compromised: {victim_count}")
except Exception as e: print(f"Error: {e}")


# 5. DATA EXFILTRATION (Network Anomaly)
# ---------------------------------------------
print("\n[Use Case 5] Potential Data Exfiltration (> 100MB Transfer)")
query_exfil = """
SELECT 
    e.first_name || ' ' || e.last_name AS Employee,
    p.protocol_name,
    SUM(n.data_transfered_MB) as Total_MB
FROM Network_Usage n
JOIN Employee_Data e ON n.employee_id = e.employee_id
JOIN Protocol_Data p ON n.protocol_id = p.protocol_id
GROUP BY e.employee_id, p.protocol_name
HAVING Total_MB > 100
ORDER BY Total_MB DESC
"""
try:
    df_exfil = pd.read_sql_query(query_exfil, sql_conn)
    if not df_exfil.empty:
        print(df_exfil.to_string(index=False))
    else:
        print(">> No large transfers detected.")
except Exception as e: print(f"Error: {e}")

# 6. IMPOSSIBLE TRAVEL (Identity Anomaly)
# ---------------------------------------------
print("\n[Use Case 6] Impossible Travel Detection")
try:
    logs = list(mongo_db["Access_logs"].find({}, {"_ID": 1, "LOCATION": 1, "TIMESTAMP": 1}))
    df_logs = pd.DataFrame(logs)
    
    if not df_logs.empty:
        # Extract country safely
        df_logs['Country'] = df_logs['LOCATION'].apply(lambda x: x.get('Country') if isinstance(x, dict) else None)
        df_logs = df_logs.sort_values(by=['_ID', 'TIMESTAMP'])
        
        # Compare current row with previous row
        df_logs['Prev_Country'] = df_logs.groupby('_ID')['Country'].shift(1)
        
        # Filter for changes
        impossible = df_logs[
            (df_logs['Country'] != df_logs['Prev_Country']) & 
            (df_logs['Prev_Country'].notnull())
        ]
        
        if not impossible.empty:
            print(f">> ALERT: {len(impossible)} suspicious location jumps detected.")
            print(impossible[['_ID', 'TIMESTAMP', 'Country', 'Prev_Country']].head().to_string(index=False))
        else:
            print(">> No impossible travel patterns found.")
    else:
        print(">> No log data available.")
except Exception as e: print(f"Error: {e}")

# 7. RBAC VIOLATION (Toxic Combination)
# ---------------------------------------------
print("\n[Use Case 7] Segregation of Duties (RBAC) Violation")
# Looking for non-Finance staff accessing Payroll/Budget files
query_rbac = """
SELECT 
    e.first_name || ' ' || e.last_name AS Employee,
    e.Department,
    f.file_name
FROM File_Access fa
JOIN Employee_Data e ON fa.employee_id = e.employee_id
JOIN File_Data f ON fa.file_id = f.file_id
WHERE 
    (e.Department NOT IN ('Finance', 'HR'))
    AND 
    (f.file_name LIKE '%Budget%' OR f.file_name LIKE '%Payroll%')
"""
try:
    df_rbac = pd.read_sql_query(query_rbac, sql_conn)
    if not df_rbac.empty:
        print(df_rbac.to_string(index=False))
    else:
        print(">> No RBAC violations detected.")
except Exception as e: print(f"Error: {e}")

# 8. ENDPOINT VULNERABILITY (New Schema Analysis)
# ---------------------------------------------
print("\n[Use Case 8] Endpoint Vulnerability Management")
query_vuln = """
SELECT 
    e.first_name || ' ' || e.last_name AS Owner,
    s.os_name,
    s.os_version,
    s.antivirus_status
FROM Endpoint_Security s
JOIN Employee_Data e ON s.employee_id = e.employee_id
WHERE s.antivirus_status != 'Active' OR s.os_version IN ('XP', '7')
"""
try:
    df_vuln = pd.read_sql_query(query_vuln, sql_conn)
    if not df_vuln.empty:
        print(f">> ALERT: {len(df_vuln)} devices require immediate patching.")
        print(df_vuln.to_string(index=False))
    else:
        print(">> All devices healthy.")
except Exception as e: print(f"Error: {e}")

print("\n=======================================================")
print("   ANALYSIS COMPLETE")
print("=======================================================")

# CLEANUP
sql_conn.close()
mongo_client.close()