**Software Requirements Specification (SRS)**

**Pocket Packet Sniffer**

**Project:** Pocket Packet Sniffer — Wi-Fi / Ethernet Packet Sniffing & Analysis Dashboard

**Version:** 1.0

**Authors: CHINMAYI HEBBAR AM, HAMZA SHABBIR SAHAPURWALA, GOWTHAM L, CHENGAPA KAIBILIRA SANTOSH**

**Date:** 03-09-2026

**Status:** Draft v1.0

## **Revision History**

| **Version** | **Date**   | **Author** | **Change Summary**                                                            | **Approval**             |
|-------------|------------|------------|-------------------------------------------------------------------------------|--------------------------|
| 0.1         | TBD        | Team Lead  | Initial draft of SRS created from project brief                               | Reviewed                 |
| 1.0         | 03-09-2026 | Team Lead  | Full SRS with FRs, NFRs, security requirements, UML use-case diagrams and RTM | Awaiting Mentor Approval |

## **Approvals**

| **Role** | **Name** | **Signature / Email** | **Date** |
|---|---|---|---|
| Team Lead / System Architect | CHINMAYI HEBBAR A M | chinmayiamc@gmail.com | 03-09-2026 |
| Embedded & Network Capture Engineer | CHENGAPA KAIBILIRA SANTOSH | chengapasantosh@gmail.com | 03-09-2026 |
| Packet Analysis Engineer | GOWTHAM L | gowtham.lsag001@gmail.com | 03-09-2026 |
| Dashboard & QA Engineer | HAMZA SHABBIR SAHAPURWALA | hamzasahapurwala@gmail.com | 03-09-2026 |

# **Table of Contents**

1\. Introduction

2\. Overall Description

3\. External Interface Requirements

4\. System Features (Detailed)

5\. Non-Functional Requirements (Detailed)

6\. Quality Attributes & Acceptance Tests

7\. System Models and Diagrams

7.1 UML Use-Case Diagrams

7.2 High-Level System Context and Data Flow

7.3 Deployment View

7.4 Core Workflow

8\. Requirements Traceability Matrix (RTM)

Appendix A. Team Roles & Work Breakdown (Jira / GitHub)

# **1. Introduction**

### **1.1 Purpose**

> This document is the Software Requirements Specification (SRS) for the Pocket Packet Sniffer (PPS) software-based packet capture, traffic analysis, and visualization system with a live dashboard. It defines the functional and non-functional requirements, interfaces, security requirements, and verification criteria for the project team, course evaluators, and future maintainers.

### **1.2 Scope**

> The system covers on-device packet capture packets from available network interfaces, performs protocol analysis and anomaly detection and integrates with Zeek , a local/embedded Python-based control and data pipeline, and a web-based dashboard for live visualization, session management, and data export. The dashboard is designed for field use by students/analysts. Out of scope: cloud-hosted multi-tenant deployment, hardware integration, decryption of TLS-protected payloads, and long-term (\>90 day) data warehousing.

### **1.3 Audience**

> Project team members (Team Lead/System Archiect, Network Capture Engineer Packet Analysis Engineer, Dashboard & QA Engineer), course instructor/evaluators, and any future student teams extending this project.

### **1.4 Definitions, Acronyms and Abbreviations**

- BLE — Bluetooth Low Energy

- Wi-Fi — Wireless local area networking (IEEE 802.11)

- Zeek — Open-source network security monitoring / traffic analysis framework (formerly Bro)

- pcap — Packet capture file format

- BPF — Berkeley Packet Filter (capture filter syntax)

- RSSI — Received Signal Strength Indicator

- OUI — Organizationally Unique Identifier (used to identify device vendor from a MAC address)

- UI — User Interface

- API — Application Programming Interface

- TLS — Transport Layer Security

- RTM — Requirements Traceability Matrix

# **2. Overall Description**

### **2.1 Product Perspective**

> Pocket Packet Sniffer is a software application that captures packets from available network interfaces, processes them using Python, analyzes traffic using Zeek, stores the results in a local database, and presents live network information through a web dashboard.

### **2.2 Major Product Functions (Summary)**

- Capture network packets from available **Wi-Fi** and **Ethernet** interfaces.

- Allow users to select the network interface and configure packet capture filters.

- Process captured packets to identify network protocols and extract relevant traffic information.

- Perform real-time traffic analysis and detect suspicious network activities using **Zeek**.

- Display live packet statistics, protocol distribution, connected devices, and security alerts through an interactive web dashboard.

- Store captured packet data, analysis results, and Zeek logs in a local database for future reference.

- Provide search, filtering, and reporting features to simplify packet analysis and investigation.

- Allow users to export captured data and analysis reports in standard formats (e.g., PCAP and CSV).

- Provide secure user authentication and access to system functionalities.

- Generate real-time notifications for detected anomalies and security events.

### **2.3 User Roles and Characteristics**

Network Administrator Responsible for

- configuring capture

- monitoring traffic

- viewing dashboard

- exporting reports

### **2.4 Operating Environment**

> Windows/Linux system with Python 3.x, Zeek installed, SQLite database, Flask/FastAPI backend, modern web browser.

### **2.5 Design and Implementation Constraints**

- Zeek must run within the resource limits , which may cap sustained analysis throughput.

- The team may only capture traffic on networks/devices it owns or has explicit permission to test, per institutional policy and law.

- Languages/tooling fixed by project brief: Python (capture, backend, glue logic), Zeek (traffic analysis).

# **3. External Interface Requirements**

### **3.1 User Interfaces**

> Primary interface: a responsive web dashboard (desktop and mobile browser), showing live capture status, traffic statistics, discovered devices, and alerts. Secondary interface: a command-line interface (CLI) on the Pi for setup, diagnostics, and headless operation.

### **3.2 Hardware Interfaces**

- No dedicated hardware interfaces are required. The application uses the host computer's available network interfaces.

### **3.3 Software Interfaces**

- Zeek process/CLI — invoked by the Python control layer to analyze pcap streams and emit logs (conn.log, dns.log, http.log, ssl.log, weird.log, notice.log)

- Internal REST/WebSocket API (Python backend, e.g., Flask/FastAPI) — serves the dashboard with live stats and controls capture sessions

- Local data store (SQLite/flat files) — session metadata, parsed device/alert records

### **3.4 Communications Interfaces**

- The web dashboard communicates with the backend through **RESTful APIs** for user requests, packet retrieval, and system management.

- **WebSocket** communication is used to provide real-time updates of captured packets, traffic statistics, and security alerts without requiring page refreshes.

- Communication between the frontend and backend occurs over the **local host** or a **Local Area Network (LAN)** using standard **HTTP/HTTPS** protocols.

- When HTTPS is enabled, **Transport Layer Security (TLS)** is used to ensure secure communication between the client and the application.

- The system supports local deployment, allowing authorized users to access the dashboard through a web browser on the same machine or within the same network.

> Note: overall project provides 21 Functional Requirements (≥ 15 required), 6 Non-Functional Requirements (≥ 5 required), 3 Security Objectives (2–4 required) and 6 Security Requirements (≥ 5 required) — see Sections 4, 5 and 5.1.

# **4. System Features (Detailed)**

> *Each requirement below includes its acceptance criteria and a reference test case. IDs follow PPS-F-###.*

## **4.1 Packet Capture (Multi-Interface)**

> Description: capture network traffic from **Wi-Fi and Ethernet interfaces** and forward it to the analysis pipeline.

<table>
<colgroup>
<col style="width: 9%" />
<col style="width: 21%" />
<col style="width: 8%" />
<col style="width: 8%" />
<col style="width: 13%" />
<col style="width: 21%" />
<col style="width: 17%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Req ID</strong></th>
<th><strong>Requirement (shall...)</strong></th>
<th><strong>Type</strong></th>
<th><strong>Priority</strong></th>
<th><strong>Source / Stakeholder</strong></th>
<th><strong>Acceptance Criteria / Test Case Ref</strong></th>
<th><strong>Comments / Dependencies</strong></th>
</tr>
<tr class="odd">
<th>PPS-F-001</th>
<th>The system shall capture Wi-Fi traffic from the user-selected network interface.</th>
<th>Functional</th>
<th>High</th>
<th>Project Brief</th>
<th><p>Packet capture starts successfully on the selected network interface and generates a valid PCAP file.</p>
<p><strong>Test:</strong> TC-CAP-01</p></th>
<th>Requires a valid and accessible network interface.</th>
</tr>
<tr class="header">
<th>PPS-F-002</th>
<th>The system shall allow the user to start and stop packet capture sessions through the application interface.</th>
<th>Functional</th>
<th>High</th>
<th>Project Brief</th>
<th><p>The selected network interface begins capturing packets within 5 seconds of starting the session.</p>
<p><strong>Test:</strong> TC-CAP-02</p></th>
<th>Requires Python packet capture libraries (e.g., Scapy or PyShark) and appropriate permissions to capture network traffic.</th>
</tr>
<tr class="odd">
<th>PPS-F-003</th>
<th>The system shall capture Ethernet traffic via an inline tap or mirrored switch port when connected via RJ45.</th>
<th>Functional</th>
<th>High</th>
<th>Project Brief</th>
<th><p>Captured Ethernet packets are correctly recorded in the generated PCAP file.</p>
<p><strong>Test:</strong> TC-CAP-03</p></th>
<th>Requires access to the target network interface.</th>
</tr>
<tr class="header">
<th>PPS-F-004</th>
<th>The system shall allow the user to select and switch between capture interfaces (Wi-Fi/Ethernet) from the dashboard or CLI.</th>
<th>Functional</th>
<th>High</th>
<th>Field Analyst</th>
<th>Switching interface stops the current session cleanly and starts the new one within 3s. Test: TC-CAP-04</th>
<th>Depends on PPS-F-001..003</th>
</tr>
<tr class="odd">
<th>PPS-F-005</th>
<th>The system shall apply user-defined BPF-style capture filters to limit captured traffic by protocol, host or port.</th>
<th>Functional</th>
<th>Medium</th>
<th>Field Analyst</th>
<th>A filter of 'tcp port 80' captures only HTTP traffic in a controlled test. Test: TC-CAP-05</th>
<th>Supports packet capture from available Wi-Fi and Ethernet network interfaces.</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

## **4.2 Traffic Analysis & Zeek Integration**

> Description: analyze captured traffic using Zeek and produce structured, queryable logs and alerts.

| **Req ID** | **Requirement (shall...)**                                                                                                                                                               | **Type**   | **Priority** | **Source / Stakeholder** | **Acceptance Criteria / Test Case Ref**                                                                                                                                | **Comments / Dependencies**                          |
|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|--------------|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| PPS-F-006  | The system shall feed captured packets (pcap) into Zeek for protocol analysis and logging in near real time.                                                                             | Functional | High         | Project Brief            | AC-PPS-F-006: Zeek logs begin appearing within 10s of capture start for an active session. Test: TC-ZEEK-01                                                            | Requires Zeek installed on system.                   |
| PPS-F-007  | The system shall generate applicable standard Zeek logs (including conn.log, dns.log, http.log, ssl.log, weird.log) for each capture session containing the corresponding traffic types. | Functional | High         | Project Brief            | AC-PPS-F-007: All five log files are present and non-empty for a session containing that traffic type. Test: TC-ZEEK-02                                                | Log set may extend as needed                         |
| PPS-F-008  | The system shall detect and flag anomalous or policy-defined suspicious traffic patterns (e.g., port scans or suspicious plaintext application data) using Zeek scripts.                 | Functional | High         | Security                 | AC-PPS-F-008: A simulated port-scan test generates a notice.log entry within the session. Test: TC-ZEEK-03                                                             | Custom Zeek scripts required                         |
| PPS-F-009  | The system shall parse Zeek logs and captured packet metadata into a normalized internal data model for dashboard visualization and reporting.                                           | Functional | High         | Dashboard Engineer       | **AC-PPS-F-009:** Parsed records shall match the expected schema for all sample Zeek log entries and captured packet metadata. **Test:** TC-ZEEK-04                    | Depends on PPS-F-007                                 |
| PPS-F-010  | The system shall identify and display information about active network hosts, including IP address, MAC address (when available), protocol, and traffic statistics.                      | Functional | Medium       | Field Analyst            | **AC-PPS-F-010:** The dashboard shall correctly display the detected host information and associated traffic statistics for all captured devices. **Test:** TC-ZEEK-05 | Requires successful packet capture and Zeek analysis |

## **4.3 Dashboard & Visualization**

> Description: provide a live, browser-based dashboard for monitoring and controlling capture sessions.

| **Req ID** | **Requirement (shall...)**                                                                                                                                                             | **Type**   | **Priority** | **Source / Stakeholder** | **Acceptance Criteria / Test Case Ref**                                                                                                                                   | **Comments / Dependencies** |
|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|--------------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------|
| PPS-F-011  | The dashboard shall display live traffic statistics (packets/sec, top talkers, protocol breakdown) during an active session.                                                           | Functional | High         | Field Analyst            | AC-PPS-F-011: Stats refresh at least every 2s and match Zeek/pcap ground truth within 5%. Test: TC-DASH-01                                                                | Depends on PPS-F-009        |
| PPS-F-012  | The dashboard shall display a live list of active network hosts and captured packet information, including IP address, MAC address (when available), protocol, and connection details. | Functional | High         | Field Analyst            | A**C-PPS-F-012:** Newly detected network hosts and captured packet information shall appear on the dashboard within **5 seconds** of being observed. **Test:** TC-DASH-02 | Depends on PPS-F-010        |
| PPS-F-013  | The dashboard shall allow users to start, stop and pause capture sessions and select the network interfaces via UI controls.                                                           | Functional | High         | Field Analyst            | AC-PPS-F-013: All control actions reflect the correct session state within 2s. Test: TC-DASH-03                                                                           | Depends on PPS-F-004        |
| PPS-F-014  | The dashboard shall visualize Zeek-flagged security alerts and anomalies with severity level and timestamp.                                                                            | Functional | High         | Security                 | AC-PPS-F-014: A generated notice.log entry appears as an alert card within 5s, with correct severity. Test: TC-DASH-04                                                    | Depends on PPS-F-008        |

## 

## 

## 

## 

## **4.4 Data Storage & Export**

> Description: persist capture sessions locally and allow export for offline review/reporting.

| **Req ID** | **Requirement (shall...)**                                                                                                                   | **Type**   | **Priority** | **Source / Stakeholder** | **Acceptance Criteria / Test Case Ref**                                                                                                                                                                       | **Comments / Dependencies**               |
|------------|----------------------------------------------------------------------------------------------------------------------------------------------|------------|--------------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------|
| PPS-F-015  | The system shall store raw pcap files and Zeek logs locally with a configurable retention period.                                            | Functional | High         | Admin                    | AC-PPS-F-015: Sessions older than the configured retention are automatically purged. Test: TC-DATA-01                                                                                                         | Depends on available storage (PPS-NF-006) |
| PPS-F-016  | The system shall allow users to export session data (PCAP files, Zeek logs, and CSV reports) through the web dashboard or local file system. | Functional | Medium       | Course Evaluator         | **AC-PPS-F-016:** Exported PCAP, Zeek logs, and CSV reports shall open correctly in compatible applications (e.g., Wireshark, spreadsheet software) and match the captured session data. **Test:** TC-DATA-02 | \-                                        |
| PPS-F-017  | The system shall support session tagging/naming and historical session browsing from the dashboard.                                          | Functional | Medium       | Field Analyst            | AC-PPS-F-017: A named, tagged session can be retrieved and re-opened from the session history view. Test: TC-DATA-03                                                                                          | \-                                        |

## 

## **4.5 System Management & User Operations** 

> Description: The system shall provide features for managing packet capture sessions, application settings, user access, and system operations to ensure reliable and efficient usage.

| **Req ID** | **Requirement (shall...)**                                                                                                                           | **Type**   | **Priority** | **Source / Stakeholder**    | **Acceptance Criteria / Test Case Ref**                                                                                            | **Comments / Dependencies**      |
|------------|------------------------------------------------------------------------------------------------------------------------------------------------------|------------|--------------|-----------------------------|------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| PPS-F-018  | The system shall allow users to configure and save packet capture settings, including the selected network interface and capture filters.            | Functional | High         | Project Brief (Portability) | AC-PPS-F-018: Saved capture settings shall be successfully applied when a new capture session is started. Test: TC-SYS-01          | Depends on PPS-F-004             |
| PPS-F-019  | The system shall provide authenticated users with access to the web dashboard through a supported web browser on the local machine or local network. | Functional | High         | Field Analyst               | AC-PPS-F-019: An authenticated user shall successfully access the dashboard from a supported browser. Test: TC-SYS-02              | Depends on authentication module |
| PPS-F-020  | The system shall allow users to safely start, stop, and terminate packet capture sessions without data loss or corruption. .                         | Functional | Medium       | Admin                       | AC-PPS-F-020: Ten consecutive capture start/stop operations shall complete without packet loss or data corruption. Test: TC-SYS-03 | Depends on PPS-F-015             |

## 

## 

## 

## 

## **4.6 Access Control**

> Description: Restrict access to the dashboard and system functionalities to authenticated users.

| **Req ID** | **Requirement (shall...)**                                                                                                                        | **Type**   | **Priority** | **Source / Stakeholder** | **Acceptance Criteria / Test Case Ref**                                                                                                                                         | **Comments / Dependencies** |
|------------|---------------------------------------------------------------------------------------------------------------------------------------------------|------------|--------------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------|
| PPS-F-021  | The system shall require user authentication (username/password) before allowing access to the dashboard and packet capture management functions. | Functional | High         | Security                 | AC-PPS-F-021: Unauthenticated users attempting to access protected dashboard pages or packet capture controls shall receive an HTTP 401 Unauthorized response. Test: TC-AUTH-01 | Depends on PPS-SR-001       |

# 

# **5. Non-Functional Requirements (Detailed)**

> *NFRs below are measurable and tied to test plans. IDs follow PPS-NF-###.*

| **Req ID** | **Requirement**                                                                                                                                                                                   | **Category**          | **Priority** | **Acceptance Criteria / Measurement**                                                                                                        |
|------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------|--------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| PPS-NF-001 | Dashboard shall reflect live traffic statistics with ≤ 2 second end-to-end latency under normal capture load (up to 20 Mbps).                                                                     | Performance           | High         | Latency measured client-to-capture in a production-like test. Test: TC-PERF-01                                                               |
| PPS-NF-002 | The application shall be compatible with Windows and Linux operating systems and run using Python 3.x with Zeek installed.                                                                        | Portability           | High         | The application shall install and execute successfully on supported operating systems without requiring code modifications. Test: TC-COMP-01 |
| PPS-NF-003 | The system shall support continuous packet capture sessions of at least 4 hours without crashes, memory leaks, or data loss.                                                                      | Reliability           | High         | Execute a 4-hour continuous capture session and verify successful operation with complete PCAP and Zeek log integrity. Test: TC-REL-01       |
| PPS-NF-004 | The dashboard shall be usable on both desktop and mobile browsers (responsive layout) without any client-side installation.                                                                       | Usability             | Medium       | Manual test on ≥ 2 desktop and ≥ 2 mobile viewport sizes. Test: TC-UX-01                                                                     |
| PPS-NF-005 | The codebase shall follow a modular architecture (capture / analysis / backend / dashboard) with documented interfaces between modules.                                                           | Maintainability       | Medium       | Architecture review + module-level README/API docs present for each of the 4 modules. Test: TC-MAINT-01                                      |
| PPS-NF-006 | The system shall manage capture-session storage through configurable log rotation and retention policies while supporting capture sessions up to 5 GB without noticeable performance degradation. | Scalability / Storage | Medium       | Keep the existing acceptance criterion.                                                                                                      |

# 

# **5.1 Security**

## **5.1.1 Security Objectives**

- SEC-OBJ-01: Protect captured data (pcap files, Zeek logs, exported reports) at rest from unauthorized access or tampering.

- SEC-OBJ-02: Ensure only authenticated and authorized users can start/stop capture sessions, change configuration, or view captured traffic and alerts.

- SEC-OBJ-03: Protect the application and its web dashboard from unauthorized access, malicious requests, and misuse while ensuring secure communication and safe handling of captured network data.

## **5.1.2 Security Requirements**

| **Req ID** | **Requirement (shall...)**                                                                                                                                                    | **Type** | **Priority** | **Acceptance Criteria / Test Case Ref**                                                                                                                               |
|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|--------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| PPS-SR-001 | Dashboard access shall require authentication; credentials shall be stored using a salted, industry-standard hash (e.g., bcrypt/argon2).                                      | Security | High         | AC-PPS-SR-001: Plaintext passwords never appear in storage or logs. Test: TC-SEC-01                                                                                   |
| PPS-SR-002 | Communication between the web dashboard and the backend shall use HTTPS/TLS where supported to protect transmitted data and user credentials.                                 | Security | High         | AC-PPS-SR-002:Network traffic between the client and the application shall not expose credentials or sensitive data in plaintext. Test: TC-SEC-02                     |
| PPS-SR-003 | Stored PCAP files, Zeek logs, and exported reports shall be access-restricted to authorized users. Optional encryption at rest shall be available for exported archives.      | Security | High         | AC-PPS-SR-003: File permission audit shows no world-readable capture data. Test: TC-SEC-03                                                                            |
| PPS-SR-004 | The application shall require the administrator to create secure login credentials during initial setup, and no credentials or secrets shall be hardcoded in the source code. | Security | High         | AC-PPS-SR-004: Static code analysis shall detect no hardcoded secrets, and the initial setup shall require the creation of administrator credentials. Test: TC-SEC-04 |
| PPS-SR-005 | Captured sensitive payloads (e.g., plaintext credentials detected by Zeek) shall be redacted or masked in default dashboard views.                                            | Security | Medium       | AC-PPS-SR-005: Simulated plaintext-credential test traffic is masked in the alert detail view by default. Test: TC-SEC-05                                             |
| PPS-SR-006 | The system shall log all administrative actions (session start/stop, configuration changes, exports, login attempts) for audit purposes.                                      | Security | Medium       | AC-PPS-SR-006: Audit log contains an entry for every administrative action performed during test scenario. Test: TC-SEC-06                                            |

# **6. Quality Attributes & Acceptance Tests**

**6.1 Quality Attributes**

| **Quality Attribute** | **Project Target**                                                                                                                                                                                         |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Performance           | Responsive dashboard and analysis pipeline; live traffic statistics and alerts shall meet the latency requirement defined in PPS-NF-001.                                                                   |
| Reliability           | The system shall complete long-duration packet capture sessions without crashes, data loss, or corruption of captured data and analysis logs.                                                              |
| Usability             | A user shall be able to start and stop packet capture, view traffic statistics, inspect alerts, and export reports through the web dashboard without requiring command-line interaction.                   |
| Maintainability       | The application shall follow a modular architecture consisting of Packet Capture, Traffic Analysis, Backend, Dashboard, and Data Storage modules with well-documented interfaces.                          |
| Compatibility         | The application shall run on supported operating systems (Windows and Linux) with Python 3.x and Zeek installed, while keeping deployment-specific configuration separate from the core application logic. |
| Security & Privacy    | Authentication, authorization, audit logging, input validation, and protection of captured network data shall be implemented and verified through security testing.                                        |

> **6.2 Exit Criteria**

- All High-priority functional requirements implemented and verified.

- No critical/High-priority NFR or security-requirement failures outstanding.

- The Requirements Traceability Matrix (Section 8) shows all listed test cases passed (status = P).

> **6.3 Acceptance Test Suites**

- **Capture:** TC-CAP-01..05 *(Wi-Fi and Ethernet packet capture, interface selection, session control, packet filtering)*

- **Analysis:** TC-ZEEK-01..05 *(Zeek integration, log generation, anomaly detection, packet parsing, host identification)*

- **Dashboard:** TC-DASH-01..04 *(live traffic statistics, network host information, session controls, security alerts)*

- **Data:** TC-DATA-01..03 (retention, export, session history)

- **System Management:** TC-SYS-01..03 *(capture configuration, authenticated dashboard access, safe session management)*

- **Performance/Reliability:** TC-PERF-01, TC-REL-01, TC-STOR-01

- **Security:** TC-SEC-01..06, TC-AUTH-01

- **Usability/Maintainability:** TC-UX-01, TC-MAINT-01

# **7. System Models and Diagrams**

## **7.1 UML Use-Case Diagrams**

> Two UML use-case diagrams are provided below, illustrating the primary functionalities of the **Pocket Packet Sniffer**. The first diagram focuses on packet capture and configuration, while the second diagram represents network analysis, monitoring, and reporting features available through the web dashboard.
>
> **Diagram 1 — Packet Capture & Configuration**

<img src="media/image2.png" style="width:5.625in;height:3.90625in" />

*Figure 1. UML Use-Case Diagram 1 — Packet Capture & Configuration*

***Primary Actor:** Network Administrator/User*

***Description:  
** The Network Administrator logs into the system, configures packet capture settings, selects the network interface, applies capture filters, starts or stops packet capture sessions, and saves the captured logs for future analysis. Key relationships include **Start Capture** including **Configure Settings**, **Select Interface**, and **Apply Filters**, while **Save Logs** is performed after a capture session is completed.*

### **Diagram 2 — Analysis and Monitoring**

<img src="media/image1.png" style="width:5.55208in;height:3.78125in" />

*Figure 2. UML Use-Case Diagram 2 — Analysis & Monitoring*

> ***Primary Actor:** Network Administrator/User*

***Description:  
** The Network Administrator monitors captured network traffic through the dashboard by viewing packet details, traffic statistics, security alerts, and protocol information. The user can search or filter captured packets and export analysis reports. Key relationships include **View Dashboard** including **View Packet Details**, **View Statistics**, and **View Alerts**, while **Export Reports** is performed after reviewing the captured and analyzed data.*

**7.2 High-Level System Context and Data Flow**

The context view illustrates the interaction between the user, the packet capture module, the Python processing layer, the Zeek analysis engine, the web dashboard, and local storage, showing how network traffic flows through the system. .

<img src="media/image4.png" style="width:5.77431in;height:3.08136in" />

*Figure 1. High-level system context and data flow.*

**7.3 Deployment View**

The deployment view illustrates the software architecture, showing the interaction between the packet capture module, Python backend, Zeek analysis service, web dashboard, and local storage within the application environment.

<img src="media/image3.png" style="width:4.13542in;height:3.32292in" />

*Figure 4. Deployment view for the portable packet sniffer.*

**7.4 Core Workflow**

### **7.4 Core Workflow**

1.  The user authenticates to the web dashboard and selects an available network interface on the host system.

2.  The Capture Manager initializes packet capture on the selected network interface and begins collecting network traffic.

3.  The Python processing layer timestamps and normalizes captured packet metadata, updates traffic statistics, and prepares the captured traffic for analysis.

4.  Captured traffic is supplied to the Zeek analysis engine for protocol identification, traffic analysis, and generation of structured logs.

5.  The Detection Engine evaluates analyzed traffic and Zeek-generated events against configured detection rules and generates security alerts when suspicious or anomalous conditions are identified.

6.  The backend updates the web dashboard with live traffic statistics, protocol information, discovered network hosts, security alerts, and the current capture-session status.

7.  Capture files, Zeek logs, normalized analysis data, session metadata, and security-relevant administrative actions are stored locally for historical review, search, and export.

8.  The user can stop the capture session and export the required PCAP files, Zeek logs, or analysis reports through the dashboard.

# **8. Requirements Traceability Matrix (RTM)**

> *Status legend: N = Not tested, P = Passed, A = At risk / failed.*

| **Req ID** | **Requirement (short)**           | **Section Ref / Design Spec** | **Module**               | **Test Case(s)** | **Status (N/P/A)** | **Comments**                                                                            |
|------------|-----------------------------------|-------------------------------|--------------------------|------------------|--------------------|-----------------------------------------------------------------------------------------|
| PPS-F-001  | Functional requirement F-001      | 4 / DS-Capture-01             | Interface Discovery      | TC-CAP-01        | N                  | Detects available Wi-Fi and Ethernet interfaces on the host system                      |
| PPS-F-002  | Functional requirement F-002      | 4 / DS-Capture-02             | Capture Config           | TC-CAP-02        | N                  | User selects the network interface for packet capture                                   |
| PPS-F-003  | Functional requirement F-003      | 4 / DS-Capture-03             | Capture Manager          | TC-CAP-03        | N                  | Captures Ethernet traffic through an available host network interface                   |
| PPS-F-004  | Functional requirement F-004      | 4 / DS-Capture-04             | Capture Manager          | TC-CAP-04        | N                  | Supports switching between available Wi-Fi and Ethernet interfaces                      |
| PPS-F-005  | Functional requirement F-005      | 4 / DS-Capture-05             | Capture Filter           | TC-CAP-05        | N                  | BPF-style filtering; Wi-Fi/Ethernet                                                     |
| PPS-F-006  | Functional requirement F-006      | 4 / DS-Zeek-01                | Zeek Adapter             | TC-ZEEK-01       | N                  | Captured PCAP data is supplied to Zeek for analysis                                     |
| PPS-F-007  | Functional requirement F-007      | 4 / DS-Zeek-02                | Zeek Adapter             | TC-ZEEK-02       | N                  | Generates applicable Zeek logs for captured traffic                                     |
| PPS-F-008  | Functional requirement F-008      | 4 / DS-Zeek-03                | Detection Engine         | TC-ZEEK-03       | N                  | Custom Zeek detection scripts identify suspicious traffic patterns                      |
| PPS-F-009  | Functional requirement F-009      | 4 / DS-Zeek-04                | Normalizer               | TC-ZEEK-04       | N                  | Normalizes Zeek logs and packet metadata for application use l                          |
| PPS-F-010  | Functional requirement F-010      | 4 / DS-Zeek-05                | Device Profiler          | TC-ZEEK-05       | N                  | Displays available host information and associated traffic statistics                   |
| PPS-F-011  | Functional requirement F-011      | 4 / DS-Dash-01                | Dashboard                | TC-DASH-01       | N                  | Displays live traffic statistics                                                        |
| PPS-F-012  | Functional requirement F-012      | 4 / DS-Dash-02                | Dashboard                | TC-DASH-02       | N                  | Displays active network hosts and packet information                                    |
| PPS-F-013  | Functional requirement F-013      | 4 / DS-Dash-03                | Dashboard                | TC-DASH-03       | N                  | Provides capture-session controls and network-interface selection                       |
| PPS-F-014  | Functional requirement F-014      | 4 / DS-Dash-04                | Alert Panel              | TC-DASH-04       | N                  | Displays Zeek-generated security alerts and anomalies                                   |
| PPS-F-015  | Functional requirement F-015      | 4 / DS-Data-01                | Storage Manager          | TC-DATA-01       | N                  | Local storage, retention, and automatic rotation of session data                        |
| PPS-F-016  | Functional requirement F-016      | 4 / DS-Data-02                | Export Service           | TC-DATA-02       | N                  | Exports PCAP files, Zeek logs, and CSV reports                                          |
| PPS-F-017  | Functional requirement F-017      | 4 / DS-Data-03                | Session Manager          | TC-DATA-03       | N                  | Session naming, tagging, and historical session browsing                                |
| PPS-F-018  | Functional requirement F-018      | 4 / DS-Power-01               | Power Manager            | TC-PWR-01        | N                  | Saves and applies packet capture settings and filters                                   |
| PPS-F-019  | Functional requirement F-019      | 4 / DS-Power-02               | Headless Access          | TC-PWR-02        | N                  | Authenticated users can access the dashboard through a supported browser                |
| PPS-F-020  | Functional requirement F-020      | 4 / DS-Power-03               | Power Manager            | TC-PWR-03        | N                  | Capture sessions can be safely started, stopped, and terminated without data corruption |
| PPS-F-021  | Functional requirement F-021      | 4 / DS-Auth-01                | Auth Module              | TC-AUTH-01       | N                  | Protected dashboard and capture-management access                                       |
| PPS-NF-001 | Non-functional requirement NF-001 | 5 / {ds}                      | Dashboard / Analysis     | TC-PERF-01       | N                  | ≤2 s dashboard latency at normal capture load                                           |
| PPS-NF-002 | Non-functional requirement NF-002 | 5 / {ds}                      | Power / Enclosure        | TC-PORT-01       | N                  | Application runs on supported Windows and Linux systems without code modifications      |
| PPS-NF-003 | Non-functional requirement NF-003 | 5 / {ds}                      | All Core Modules         | TC-REL-01        | N                  | 4-hour continuous capture without crashes, memory leaks, or data loss                   |
| PPS-NF-004 | Non-functional requirement NF-004 | 5 / {ds}                      | Dashboard                | TC-UX-01         | N                  | Responsive dashboard on desktop and mobile browsers                                     |
| PPS-NF-005 | Non-functional requirement NF-005 | 5 / {ds}                      | Architecture             | TC-MAINT-01      | N                  | Module interfaces documented                                                            |
| PPS-NF-006 | Non-functional requirement NF-006 | 5 / {ds}                      | Storage Manager          | TC-STOR-01       | N                  | Supports configurable retention and capture sessions up to 5 GB                         |
| PPS-SR-001 | Security requirement SR-001       | 5.1.2 / DS-Sec-01             | Auth Module              | TC-SEC-01        | N                  | Credentials stored using secure password hashing                                        |
| PPS-SR-002 | Security requirement SR-002       | 5.1.2 / DS-Sec-02             | Transport Security       | TC-SEC-02        | N                  | HTTPS/TLS protects dashboard-backend communication where supported                      |
| PPS-SR-003 | Security requirement SR-003       | 5.1.2 / DS-Sec-03             | Storage / OS Permissions | TC-SEC-03        | N                  | Capture files and analysis data are restricted to authorized users                      |
| PPS-SR-004 | Security requirement SR-004       | 5.1.2 / DS-Sec-04             | First-Run Security       | TC-SEC-04        | N                  | No default or hardcoded credentials/secrets                                             |
| PPS-SR-005 | Security requirement SR-005       | 5.1.2 / DS-Sec-05             | Dashboard / Redaction    | TC-SEC-05        | N                  | Sensitive fields are masked by default                                                  |
| PPS-SR-006 | Security requirement SR-006       | 5.1.2 / DS-Sec-06             | Audit Logger             | TC-SEC-06        | N                  | Administrative actions are recorded for auditing                                        |

# **Appendix A. Team Roles & Work Breakdown (Jira / GitHub)**

> This project is delivered by a 4-member team (1 Team Lead + 3 members). Work is divided along the system's natural module boundaries so each member owns an end-to-end slice they can build, test and demo independently, while the Team Lead owns integration, security, and delivery tracking.

## **A.1 Roles & Requirement Ownership**

| **Role**                     | **Team Member**            | **Primary Module(s)**                                                                                                           | **Requirement IDs Owned**                  |
|------------------------------|----------------------------|---------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------|
| Team Lead / Integration Lead | CHINMAYI HEBBAR AM         | System integration, architecture, Jira & GitHub administration, Security                                                        | PPS-F-021, PPS-SR-001..006, PPS-NF-005     |
| Hardware & Firmware Engineer | CHENGAPA KAIBILIRA SANTOSH | Python-based packet capture, Wi-Fi/Ethernet interface configuration, packet filtering, packet logging, backend integration      | PPS-F-001..005, PPS-F-018..020, PPS-NF-002 |
| Data Pipeline Engineer       | GOWTHAM L                  | Python packet processing, Zeek integration, protocol analysis, threat detection, alerts, traffic statistics                     | PPS-F-006..010, PPS-F-015..017, PPS-NF-006 |
| Dashboard Engineer / QA      | HAMZA SHABBIR SAHAPURWALA  | Dashboard development, data visualization, frontend integration, testing, Requirements Traceability Matrix (RTM), documentation | PPS-F-011..014, PPS-NF-001, PPS-NF-004     |

> *The Team Lead also contributes hands-on to backend/authentication work, while each member acts as the primary reviewer for at least one other member’s pull requests*

## **A.2 Suggested Jira Epic / Sprint Structure**

| **Epic**                           | **Example Stories / Tasks**                                                                                                                                               | **Owner**                  | **Sprint** |
|------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------|------------|
| EPIC-1: Network Capture Layer      | Set up Python packet-capture environment; detect available Wi-Fi/Ethernet interfaces; interface selection and switching; BPF packet filtering; packet capture and logging | Network Capture Engineer   | Sprint 1–2 |
| EPIC-2: Packet Analysis Pipeline   | Install/configure Zeek; pcap→Zeek pipeline; custom detection scripts; log parser; protocol analysis; threat detection and alerts                                          | Packet Analysis Engineer   | Sprint 1–3 |
| EPIC-3: Dashboard & UX             | Backend API (session control, stats, alerts); live dashboard UI; active-host/device list; alert view; data visualization; responsive layout                               | Dashboard Engineer         | Sprint 2–4 |
| EPIC-4: Integration, Security & PM | Authentication; audit logging; TLS configuration; end-to-end integration; RTM & test execution; sprint planning/reviews                                                   | Team Lead (all contribute) | Sprint 1–4 |

### 

### **Sprint plan**

- **Sprint 1:** Development environment setup, Python packet-capture setup, Zeek installation/configuration, project skeleton (backend + frontend), Jira board and GitHub repository configuration.

- **Sprint 2:** Core Wi-Fi/Ethernet packet capture working end-to-end into PCAP; initial dashboard wireframe with mock data; authentication scaffolding.

- **Sprint 3:** Zeek analysis pipeline feeding real parsed data into the backend/dashboard; protocol analysis, alerts and active-host information implemented; security requirements integrated.

- **Sprint 4:** Performance and reliability testing, RTM sign-off, bug fixing, end-to-end integration, final documentation and demo.

Recommended Jira hygiene: one board with the 4 epics above, story points per task, and each story linked to its requirement ID (e.g., PPS-F-006) in the description so the RTM in Section 8 stays traceable to Jira.

## **A.3 GitHub Repository & Branching Strategy**

Suggested monorepo layout so all four modules stay versioned together and CI can build the whole system:

- **/capture** — Python packet-capture scripts, interface detection, filtering and packet logging (**Network Capture Engineer**)

- **/analysis** — Zeek scripts/policies, Python packet processing and log parsers (**Packet Analysis Engineer**)

- **/backend** — Python REST/WebSocket API, authentication, session control and storage logic (**Team Lead + Network Capture Engineer**)

- **/dashboard** — Web frontend, dashboard UI and data visualization (**Dashboard & QA Engineer**)

- **/docs** — SRS, design specifications, UML diagrams, meeting notes and project documentation

**Branching:** main (protected, always demo-able) ← develop ← feature/PPS-F-0xx-short-name branches per Jira story. Pull requests require at least 1 reviewer and passing CI before merge.

**Project safety note:** The prototype is intended for passive observation and analysis of networks/devices for which the operator has authorization. Demonstrations should use controlled lab traffic and test devices.

**Commit messages** should reference the Jira/requirement ID, e.g., PPS-F-006: wire pcap stream into Zeek process.
