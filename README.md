<h2> 📌 Project Overview </h2>

This project demonstrates a comprehensive, full-stack approach to Cybersecurity Analytics by implementing a Polyglot Persistence architecture. It simulates a real-world Security Operations Center (SOC) environment, integrating structured organizational data (SQL) with high-volume, unstructured log data (NoSQL) to detect threats that single-database systems often miss.

The system performs an automated security audit across 8 key use cases, ranging from basic hygiene monitoring to advanced threat hunting.

<h2> 🚀 Key Features & Use Cases </h2>

Phase 1: Baseline Security Monitoring

Insider Threat Detection: Flags file access outside business hours (20:00 - 08:00) to detect potential data theft or unauthorized activity.

SLA Performance KPIs: Calculates the average Incident Response time by threat type to measure SOC efficiency against Service Level Agreements.

Identity & Access Management (IAM): Identifies brute-force attacks by flagging users with repeated failed login attempts.

Phishing Vulnerability Analysis: Correlates AI-detected high-risk emails with user click behavior to identify employees requiring security awareness training.

Phase 2: Advanced Threat Hunting

Data Exfiltration Monitoring: Detects large data transfers (>100MB) via insecure protocols (e.g., FTP) to prevent IP theft.

Impossible Travel Detection: Identifying compromised credentials by flagging logins from geographically distant locations within physically impossible timeframes.

Segregation of Duties (RBAC) Violation: Audits access logs for "Toxic Combinations," such as IT staff accessing sensitive Finance or HR documents.

Endpoint Vulnerability Management: Scans the device fleet to identify machines running End-of-Life (EOL) operating systems or missing critical patches.

<h2> 📂 Repository Structure </h2>

/Hybrid-Security-Analytics
│
├── setup_all_databases.py      # Infrastructure-as-Code: Builds SQL/NoSQL DBs & generates mock data
├── full_security_analysis.py   # Analysis Engine: Runs the 8 security checks and prints the SOC report
├── config_example.py           # Configuration template (Rename to config.py)
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation
