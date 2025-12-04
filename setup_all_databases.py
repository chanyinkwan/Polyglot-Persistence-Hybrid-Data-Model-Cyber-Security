import sqlite3
import random
from datetime import datetime, timedelta, time
import subprocess
import sys
import os
import pymongo

# =========================================================================
#  HYBRID DATABASE SETUP SCRIPT
#  -----------------------------------------------------------------------
#  Purpose: Initializes the Relational (SQLite) and NoSQL (MongoDB) environments.
#  Features:
#    1. Idempotent: Drops and recreates tables/collections on every run.
#    2. Hybrid: Handles structured enterprise data and unstructured log data.
#    3. Advanced Schema: Includes Endpoint Security for vulnerability tracking.
# =========================================================================

# --- CONFIGURATION ---
SQLITE_DB_NAME = "security_db.db"
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB_NAME = "Cybersecurity_Dep"

print(f"--- Initialization: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")

# --- 1. SQLITE CONNECTION ---
try:
    cnxn = sqlite3.connect(SQLITE_DB_NAME)
    cursor = cnxn.cursor()
    cnxn.execute('PRAGMA foreign_keys = ON;') # Enforce integrity
    print(f"✅ [SQL] Connected to {SQLITE_DB_NAME}")
except Exception as e:
    print(f"❌ [SQL] Connection failed: {e}")
    sys.exit(1)

# --- 2. MONGODB CONNECTION ---
try:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pymongo"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    mongoclient = pymongo.MongoClient(MONGO_URI)
    mydb = mongoclient[MONGO_DB_NAME]
    
    # Drop existing collections for a clean slate
    mydb["Access_logs"].drop()
    mydb["Phishing_attacks"].drop()
    print(f"✅ [NoSQL] Connected to {MONGO_DB_NAME} (Collections cleared)")
except Exception as e:
    print(f"⚠️ [NoSQL] MongoDB not found. Ensure it is running locally on port 27017. Error: {e}")

# =========================================================================
#  SECTION A: RELATIONAL SCHEMA (DDL)
# =========================================================================

# 1. Drop Tables (Order matters due to Foreign Keys)
drop_tables_sql = '''
DROP TABLE IF EXISTS Incident_Detection;
DROP TABLE IF EXISTS Detected_By;
DROP TABLE IF EXISTS Detection_Method;
DROP TABLE IF EXISTS Incident_Response;
DROP TABLE IF EXISTS Security_Incidents;
DROP TABLE IF EXISTS File_Access;
DROP TABLE IF EXISTS File_Data;
DROP TABLE IF EXISTS Access_Type;
DROP TABLE IF EXISTS Network_Usage;
DROP TABLE IF EXISTS Protocol_Data;
DROP TABLE IF EXISTS Roles_Permissions;
DROP TABLE IF EXISTS Permissions;
DROP TABLE IF EXISTS Roles;
DROP TABLE IF EXISTS Endpoint_Security; 
DROP TABLE IF EXISTS Employee_Data;
'''
cursor.executescript(drop_tables_sql)

# 2. Create Tables
# Note: Endpoint_Security is added here (Phase 1 Expansion)
create_tables_sql = '''
CREATE TABLE Employee_Data (
    employee_id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    Department VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    role_ID INT NOT NULL
);

CREATE TABLE Roles (
    role_id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name VARCHAR(255) NOT NULL
);

CREATE TABLE Permissions (
    permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
    permission_description VARCHAR(255) NOT NULL
);

CREATE TABLE Roles_Permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY(role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES Roles(role_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES Permissions(permission_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE Endpoint_Security (
    device_id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INT,
    os_name VARCHAR(50),
    os_version VARCHAR(50),
    last_patch_date TEXT,
    antivirus_status VARCHAR(20),
    FOREIGN KEY (employee_id) REFERENCES Employee_Data(employee_id)
);

CREATE TABLE Protocol_Data (
    protocol_id INT PRIMARY KEY,
    protocol_name VARCHAR(255) NOT NULL
);

CREATE TABLE Network_Usage (
    network_usage_id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INT NOT NULL,
    timestamp TEXT NOT NULL, 
    data_transfered_MB FLOAT NOT NULL,
    protocol_id INT NOT NULL,
    destination_ip VARCHAR(255) NOT NULL,
    FOREIGN KEY (employee_id) REFERENCES Employee_Data(employee_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (protocol_id) REFERENCES Protocol_Data(protocol_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE Access_Type (
    access_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
    access_type_name VARCHAR(255) NOT NULL
);

CREATE TABLE File_Data (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name VARCHAR(255) NOT NULL
);

CREATE TABLE File_Access (
    access_id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INT NOT NULL,
    access_type_id INT NOT NULL,
    timestamp TEXT NOT NULL,
    file_id INT NOT NULL,
    FOREIGN KEY (employee_id) REFERENCES Employee_Data(employee_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (access_type_id) REFERENCES Access_Type(access_type_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES File_Data(file_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE Security_Incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INT NOT NULL,
    timestamp TEXT NOT NULL,
    incident_type VARCHAR(255) NOT NULL,
    resolution_status VARCHAR(255) NOT NULL,
    FOREIGN KEY (employee_id) REFERENCES Employee_Data(employee_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE Incident_Response (
    incident_response_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INT NOT NULL,
    response_start_time TEXT NOT NULL,
    response_end_time TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES Security_Incidents(incident_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE Detection_Method (
    detection_method_id INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_method_name VARCHAR(255) NOT NULL
);

CREATE TABLE Detected_By (
    detected_by_id INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_by_name VARCHAR(255) NOT NULL
);

CREATE TABLE Incident_Detection (
    incident_detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INT NOT NULL,
    detection_time TEXT NOT NULL,
    detection_method_id INT NOT NULL,
    detected_by_id INT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES Security_Incidents(incident_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (detection_method_id) REFERENCES Detection_Method(detection_method_id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (detected_by_id) REFERENCES Detected_By(detected_by_id) ON UPDATE CASCADE ON DELETE CASCADE
);
'''
cursor.executescript(create_tables_sql)
print("✅ [SQL] Schema created successfully (including Endpoint_Security).")

# =========================================================================
#  SECTION B: DATA POPULATION (DML)
# =========================================================================

# 1. Employees
EmpNames_sql = """
INSERT INTO Employee_Data (first_name, last_name, Department, email, role_ID) VALUES
('Alice', 'Johnson', 'Finance', 'alice.johnson@bank.com', 1),
('Bob', 'Smith', 'IT', 'bob.smith@bank.com', 2),
('Charlie', 'Brown', 'HR', 'charlie.brown@bank.com', 3),
('David', 'Wilson', 'Cybersecurity', 'david.wilson@bank.com', 4),
('Emma', 'Davis', 'Operations', 'emma.davis@bank.com', 5),
('Frank', 'Miller', 'Finance', 'frank.miller@bank.com', 1),
('Grace', 'Moore', 'IT', 'grace.moore@bank.com', 2),
('Hannah', 'Taylor', 'HR', 'hannah.taylor@bank.com', 3),
('Isaac', 'Anderson', 'Cybersecurity', 'isaac.anderson@bank.com', 4),
('Jack', 'Thomas', 'Operations', 'jack.thomas@bank.com', 5),
('Kelly', 'White', 'Finance', 'kelly.white@bank.com', 1),
('Liam', 'Harris', 'IT', 'liam.harris@bank.com', 2),
('Mia', 'Martin', 'HR', 'mia.martin@bank.com', 3),
('Noah', 'Thompson', 'Cybersecurity', 'noah.thompson@bank.com', 4),
('Olivia', 'Garcia', 'Operations', 'olivia.garcia@bank.com', 5),
('Peter', 'Martinez', 'Finance', 'peter.martinez@bank.com', 1),
('Quinn', 'Robinson', 'IT', 'quinn.robinson@bank.com', 2),
('Ryan', 'Clark', 'HR', 'ryan.clark@bank.com', 3),
('Sophia', 'Rodriguez', 'Cybersecurity', 'sophia.rodriguez@bank.com', 4),
('Tyler', 'Lewis', 'Operations', 'tyler.lewis@bank.com', 5),
('Uma', 'Lee', 'Finance', 'uma.lee@bank.com', 1),
('Victor', 'Walker', 'IT', 'victor.walker@bank.com', 2),
('Wendy', 'Hall', 'HR', 'wendy.hall@bank.com', 3),
('Xander', 'Allen', 'Cybersecurity', 'xander.allen@bank.com', 4),
('Yara', 'Young', 'Operations', 'yara.young@bank.com', 5),
('Zach', 'King', 'Finance', 'zach.king@bank.com', 1),
('Amy', 'Scott', 'IT', 'amy.scott@bank.com', 2),
('Brian', 'Green', 'HR', 'brian.green@bank.com', 3),
('Chloe', 'Adams', 'Cybersecurity', 'chloe.adams@bank.com', 4),
('Daniel', 'Baker', 'Operations', 'daniel.baker@bank.com', 5),
('Ella', 'Gonzalez', 'Finance', 'ella.gonzalez@bank.com', 1),
('Finn', 'Nelson', 'IT', 'finn.nelson@bank.com', 2),
('George', 'Carter', 'HR', 'george.carter@bank.com', 3),
('Holly', 'Mitchell', 'Cybersecurity', 'holly.mitchell@bank.com', 4),
('Ian', 'Perez', 'Operations', 'ian.perez@bank.com', 5),
('Jane', 'Roberts', 'Finance', 'jane.roberts@bank.com', 1),
('Kevin', 'Phillips', 'IT', 'kevin.phillips@bank.com', 2),
('Laura', 'Evans', 'HR', 'laura.evans@bank.com', 3),
('Mason', 'Edwards', 'Cybersecurity', 'mason.edwards@bank.com', 4),
('Natalie', 'Collins', 'Operations', 'natalie.collins@bank.com', 5),
('Oscar', 'Stewart', 'Finance', 'oscar.stewart@bank.com', 1),
('Paul', 'Morris', 'IT', 'paul.morris@bank.com', 2),
('Rebecca', 'Nguyen', 'HR', 'rebecca.nguyen@bank.com', 3),
('Samuel', 'Murphy', 'Cybersecurity', 'samuel.murphy@bank.com', 4),
('Tina', 'Rivera', 'Operations', 'tina.rivera@bank.com', 5),
('Ursula', 'Foster', 'Finance', 'ursula.foster@bank.com', 1),
('Vince', 'Hayes', 'IT', 'vince.hayes@bank.com', 2),
('Walter', 'Perry', 'HR', 'walter.perry@bank.com', 3),
('Xenia', 'Long', 'Cybersecurity', 'xenia.long@bank.com', 4),
('Yasmine', 'Bryant', 'Operations', 'yasmine.bryant@bank.com', 5),
('Zane', 'Griffin', 'Finance', 'zane.griffin@bank.com', 1),
('Ava', 'Russell', 'Finance', 'ava.russell@bank.com', 1),
('Blake', 'Simmons', 'IT', 'blake.simmons@bank.com', 2),
('Cameron', 'Barnes', 'HR', 'cameron.barnes@bank.com', 3),
('Diana', 'Henderson', 'Cybersecurity', 'diana.henderson@bank.com', 4),
('Ethan', 'Coleman', 'Operations', 'ethan.coleman@bank.com', 5),
('Fiona', 'Powell', 'Finance', 'fiona.powell@bank.com', 1),
('Gavin', 'Jenkins', 'IT', 'gavin.jenkins@bank.com', 2),
('Hailey', 'Patterson', 'HR', 'hailey.patterson@bank.com', 3),
('Isaiah', 'Hughes', 'Cybersecurity', 'isaiah.hughes@bank.com', 4);
"""
cursor.execute(EmpNames_sql)

# 2. Endpoint Security Data (New Schema Data)
# Mock data representing device health for the first 10 employees
endpoint_data = [
    (1, 'Windows', '11', '2024-03-01', 'Active'),
    (2, 'Windows', '10', '2024-02-15', 'Active'),
    (3, 'MacOS', 'Sonoma', '2024-03-10', 'Active'),
    (4, 'Windows', '7', '2020-01-14', 'Expired'), # RISK: EOL OS
    (5, 'Linux', 'Ubuntu 22.04', '2024-03-20', 'Active'),
    (6, 'Windows', '10', '2023-11-01', 'Disabled'), # RISK: Old Patch + No AV
    (7, 'Windows', '11', '2024-03-05', 'Active'),
    (8, 'MacOS', 'Ventura', '2023-12-20', 'Active'),
    (9, 'Windows', 'XP', '2014-04-08', 'Expired'), # HIGH RISK
    (10, 'Windows', '11', '2024-03-01', 'Active')
]
cursor.executemany("INSERT INTO Endpoint_Security (employee_id, os_name, os_version, last_patch_date, antivirus_status) VALUES (?, ?, ?, ?, ?)", endpoint_data)

# 3. Protocol & Access Data
cursor.execute("INSERT INTO Protocol_Data (protocol_id, protocol_name) VALUES (1, 'HTTP'), (2, 'FTP'), (3, 'SSH'), (4, 'DNS');")
cursor.execute("INSERT INTO Access_Type (access_type_name) VALUES ('Read'), ('Write'), ('Execute'), ('Modify'), ('Delete'), ('Create'), ('View'), ('Download'), ('Upload'), ('Share');")
cursor.execute("INSERT INTO Permissions (permission_description) VALUES ('View Reports'), ('Edit Reports'), ('Manage Users'), ('Access Financial Data'), ('Modify IT Infrastructure'), ('Manage HR Records'), ('Access Cybersecurity Systems'), ('Monitor Security Alerts'), ('Process Operations Requests'), ('Approve Operational Changes');")
cursor.execute("INSERT INTO Detected_By (detected_by_name) VALUES ('Security Team'), ('Automated System'), ('End User'), ('Firewall System');")
cursor.execute("INSERT INTO Detection_Method (detection_method_name) VALUES ('Automated Monitoring'), ('Intrusion Detection System'), ('User Report'), ('Firewall Alert');")

# 4. Roles & RBAC Assignment
department_roles = {
    'Finance': [(1, 'Junior Accountant'), (2, 'Mid Accountant'), (3, 'Senior Accountant'), (4, 'CFO'), (5, 'Finance Director')],
    'IT': [(6, 'Junior IT Analyst'), (7, 'Mid IT Analyst'), (8, 'Senior IT Analyst'), (9, 'IT Manager'), (10, 'CTO')],
    'HR': [(11, 'Junior HR Manager'), (12, 'Mid HR Manager'), (13, 'Senior HR Manager'), (14, 'HR Director'), (15, 'Chief HR Officer')],
    'Cybersecurity': [(16, 'Junior Cybersecurity Analyst'), (17, 'Mid Cybersecurity Analyst'), (18, 'Senior Cybersecurity Analyst'), (19, 'Cybersecurity Manager'), (20, 'Chief Security Officer')],
    'Operations': [(21, 'Junior Operations Analyst'), (22, 'Mid Operations Analyst'), (23, 'Senior Operations Analyst'), (24, 'Operations Manager'), (25, 'COO')]
}

cursor.execute("DELETE FROM Roles") # Clean slate
for department, roles in department_roles.items():
    for role_id, role_name in roles:
        cursor.execute("INSERT INTO Roles (role_ID, role_name) VALUES (?, ?)", (role_id, role_name))

# Assign random roles to employees based on their department
cursor.execute("SELECT employee_id, email, Department FROM Employee_Data")
employees = cursor.fetchall()
role_ranges = {'Finance': (1, 5), 'IT': (6, 10), 'HR': (11, 15), 'Cybersecurity': (16, 20), 'Operations': (21, 25)}

for employee_id, email, department in employees:
    if department in role_ranges:
        new_role_ID = random.randint(*role_ranges[department])
        cursor.execute("UPDATE Employee_Data SET role_ID = ? WHERE employee_id = ?", (new_role_ID, employee_id))

# Link Permissions to Roles
permissions_for_employees = {
    'Alice Johnson': [6, 5], 'Amy Scott': [1, 2], 'Bob Smith': [1, 2], 'Brian Green': [3, 4], 
    'David Wilson': [7, 8], 'Frank Miller': [4, 3], 'Gavin Jenkins': [1, 2], 'Holly Mitchell': [7, 8],
    'Isaac Anderson': [7, 8], 'Kevin Phillips': [9, 10], 'Mia Martin': [3, 4], 'Noah Thompson': [7, 8],
    'Oscar Stewart': [6, 5], 'Quinn Robinson': [9, 10], 'Xander Allen': [7, 8]
}

for full_name, permissions in permissions_for_employees.items():
    first_name, last_name = full_name.split()
    cursor.execute("SELECT role_ID FROM Employee_Data WHERE first_name = ? AND last_name = ?", (first_name, last_name))
    result = cursor.fetchone()
    if result:
        role_id = result[0]
        for permission_id in permissions:
            cursor.execute("SELECT COUNT(*) FROM Roles_Permissions WHERE role_id = ? AND permission_id = ?", (role_id, permission_id))
            if cursor.fetchone()[0] == 0:
                cursor.execute("INSERT INTO Roles_Permissions (role_id, permission_id) VALUES (?, ?)", (role_id, permission_id))

# 5. Inject Audit Data (Network, Files, Incidents)
# (Injecting a subset of the original massive strings for readability, enough for analysis)
NetworkInfo_sql = """
INSERT INTO Network_Usage (employee_id, timestamp, data_transfered_MB, protocol_id, destination_ip) VALUES
(32, '2024-03-24 08:15:23', 45.6, 1, '192.168.1.10'), (12, '2024-03-24 09:20:11', 12.3, 2, '10.0.0.5'),
(45, '2024-03-24 10:05:45', 205.9, 3, '172.16.0.2'), (21, '2024-03-24 11:12:32', 23.1, 1, '192.168.1.15'),
(9, '2024-03-24 12:40:21', 56.7, 4, '10.0.0.8'), (56, '2024-03-24 13:55:10', 98.2, 2, '172.16.1.3'),
(7, '2024-03-24 14:22:18', 34.5, 3, '192.168.2.20'), (48, '2024-03-24 15:30:25', 87.4, 1, '10.0.1.15'),
(19, '2024-03-24 16:45:33', 14.2, 4, '172.16.2.4'), (29, '2024-03-24 17:50:40', 150.5, 2, '192.168.3.11');
"""
cursor.executescript(NetworkInfo_sql)

FileName_sql = """
INSERT INTO File_Data (file_name) VALUES
('Sales_Report_2024_Q1.xlsx'), ('Employee_Records_2024.xlsx'), ('Budget_Overview_2024.xlsx'), 
('Payroll_Data_2024.csv'), ('IT_Security_Protocols_2024.pdf'), ('Marketing_Budgets_2024.xlsx');
"""
cursor.executescript(FileName_sql)

FileAccess_sql = """
INSERT INTO File_Access (employee_id, access_type_id, timestamp, file_id) VALUES
(7, 4, '2024-03-25 07:32:15', 1), (2, 2, '2024-03-25 09:10:53', 2), (15, 6, '2024-03-25 21:24:46', 3),
(30, 1, '2024-03-25 11:45:20', 4), (21, 5, '2024-03-25 13:05:12', 5), (12, 7, '2024-03-25 22:23:39', 6);
"""
cursor.executescript(FileAccess_sql)

Security_Incidents_sql = """
INSERT INTO Security_Incidents (employee_id, timestamp, incident_type, resolution_status) VALUES 
(5, '2024-03-25 08:20:53', 'Unauthorized Access', 'Resolved'), (12, '2024-03-28 12:32:20', 'Malware Infection', 'In Progress'),
(21, '2024-03-27 14:20:56', 'Phishing Attack', 'Resolved'), (8, '2024-03-27 10:45:39', 'Data Breach', 'Resolved'),
(36, '2024-03-27 04:10:27', 'Password Compromise', 'In Progress'), (40, '2024-03-26 07:50:20', 'Insider Threat', 'Resolved');
"""
cursor.executescript(Security_Incidents_sql)

Incident_Response_sql = """
INSERT INTO Incident_Response (incident_id, response_start_time, response_end_time) VALUES
(1, '2024-03-25 08:30:00', '2024-03-25 09:00:00'), (2, '2024-03-28 12:45:00', '2024-03-28 13:30:00'),
(3, '2024-03-27 14:30:00', '2024-03-27 15:00:00'), (4, '2024-03-27 10:50:00', '2024-03-27 11:20:00'),
(5, '2024-03-27 04:15:00', '2024-03-27 04:45:00'), (6, '2024-03-26 08:00:00', '2024-03-26 08:30:00');
"""
cursor.executescript(Incident_Response_sql)

cnxn.commit()
print("✅ [SQL] Data populated successfully.")

# =========================================================================
#  SECTION C: NOSQL LOG GENERATION
# =========================================================================

if 'mongoclient' in locals() and mongoclient is not None:
    print("\n--- Generating MongoDB Logs ---")
    
    employee_ids = [f"EMP{str(i).zfill(3)}" for i in range(1, 61)]
    vendors_ids = [f"VEND{str(i).zfill(2)}" for i in range(1, 20)]
    all_ids = employee_ids + vendors_ids
    
    statuses = ["Successful", "Failed"]
    locations = [
        {"City": "London", "Country": "UK"}, {"City": "Manchester", "Country": "UK"}, {"City": "Berlin", "Country": "Germany"},
        {"City": "Paris", "Country": "France"}, {"City": "New York", "Country": "USA"}, {"City": "Tokyo", "Country": "Japan"}
    ]
    
    # Access Logs
    access_logs = mydb["Access_logs"]
    access_logs_data = []
    # Generate some suspicious data (Impossible Travel)
    # User EMP001 logs in from London, then Tokyo 1 hour later
    access_logs_data.append({"_ID": "EMP001", "TIMESTAMP": datetime.now(), "LOCATION": {"City": "London", "Country": "UK"}, "STATUS": "Successful"})
    access_logs_data.append({"_ID": "EMP001", "TIMESTAMP": datetime.now() + timedelta(hours=1), "LOCATION": {"City": "Tokyo", "Country": "Japan"}, "STATUS": "Successful"})
    
    # Generate bulk logs
    for _ in range(200):
        access_logs_data.append({
            "_ID": random.choice(all_ids),
            "TIMESTAMP": datetime.now() - timedelta(days=random.randint(0, 30)),
            "LOCATION": random.choice(locations),
            "STATUS": random.choice(statuses)
        })
    access_logs.insert_many(access_logs_data)
    print(f"✅ [NoSQL] Inserted {len(access_logs_data)} records into 'Access_logs'.")

    # Phishing Logs
    phishing = mydb["Phishing_attacks"]
    phishing_data = [
        {
            "PHISHING_ID": f"PH{str(i).zfill(3)}",
            "_ID": random.choice(all_ids),
            "ANOMALY_SCORE": round(random.uniform(0.5, 1.0), 2),
            "LINK_CLICKED": random.choice([True, False]),
            "EMAIL_SUBJECT": "Urgent Update",
            "EMAIL_SENDER": "admin@banking.com"
        }
        for i in range(1, 101)
    ]
    phishing.insert_many(phishing_data)
    print(f"✅ [NoSQL] Inserted {len(phishing_data)} records into 'Phishing_attacks'.")

# --- CLEANUP ---
cursor.close()
cnxn.close()
if 'mongoclient' in locals() and mongoclient is not None:
    mongoclient.close()

print("SETUP COMPLETE: The Hybrid Security System is ready for analysis.")