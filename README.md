# 🛡️ API Misuse Guard

**Explainable API Security Monitoring System built with Java and Spring Boot**

API Misuse Guard is a defensive security-monitoring application that automatically observes incoming HTTP requests and authentication activity, detects suspicious behaviour, blocks selected misuse attempts, logs security events, and explains **why** each activity was considered risky.

The project demonstrates how a Spring Boot application can combine request filtering, authentication monitoring, role-based access checks, rate monitoring, persistence, and real-time event streaming.

---

## ✨ Features

* Automatic client IP detection
* USER and ADMIN authentication demo
* Role-mismatch detection
* Failed-login monitoring
* Brute-force detection
* Unauthorized ADMIN endpoint detection
* Rate Misuse detection
* Suspicious request-input detection
* LOW / MEDIUM / HIGH / CRITICAL-style risk classification
* Explainable security-event logging
* HTTP blocking with `400`, `403`, and `429` responses
* H2 database persistence during runtime
* Live security dashboard using **Server-Sent Events (SSE)**
* Real-time dashboard updates without page refresh
* Separate USER, ADMIN and Security Monitoring views

---

## 🧰 Tech Stack

| Technology      | Purpose                                       |
| --------------- | --------------------------------------------- |
| Java 21         | Core programming language                     |
| Spring Boot     | Application framework                         |
| Spring MVC      | Controllers and HTTP request handling         |
| Spring Data JPA | Database persistence                          |
| Hibernate       | ORM                                           |
| H2 Database     | Local/in-memory security-event storage        |
| Thymeleaf       | Server-rendered frontend                      |
| SSE             | Real-time server-to-dashboard event streaming |
| Maven           | Dependency management and build system        |

---

## 🏗️ Architecture

```text
                         CLIENT
                           │
                           │ HTTP Request
                           ▼
                 ┌───────────────────┐
                 │ ApiMisuseFilter   │
                 └─────────┬─────────┘
                           │
              ┌────────────┼─────────────┐
              │            │             │
              ▼            ▼             ▼
        Rate Misuse   Unauthorized   Suspicious
        Detection       Access        Input
              │            │             │
              └────────────┼─────────────┘
                           │
                           ▼
                SecurityEventService
                     │           │
                     │           │
                     ▼           ▼
                 H2 Database     SSE
                     │           │
                     │           ▼
                     │     Live Dashboard
                     │
                     ▼
                Event History
```

Authentication-related events use the same security-event pipeline:

```text
Login Request
     │
     ▼
LoginController
     │
     ├── Invalid Password
     ├── Role Mismatch
     └── Repeated Failures
             │
             ▼
      SecurityEventService
             │
        ┌────┴────┐
        ▼         ▼
       H2        SSE
                  │
                  ▼
          Security Dashboard
```

---

## 🔐 Demo Accounts

The application contains local demonstration accounts only.

### USER

```text
Username: user
Password: demo123
Role: USER
```

### ADMIN

```text
Username: admin
Password: admin123
Role: ADMIN
```

> ⚠️ Educational localhost demo only. Do not enter real credentials.

---

## 🧪 Detection Scenarios

### 1. Normal USER Login

```text
Username: user
Password: demo123
Role: USER
```

Result:

```text
Login successful
→ /profile
→ No security alert
```

---

### 2. Normal ADMIN Login

```text
Username: admin
Password: admin123
Role: ADMIN
```

Result:

```text
Login successful
→ /admin/dashboard
```

The ADMIN can access protected ADMIN resources and the security-monitoring dashboard.

---

### 3. Role Mismatch

Example:

```text
Username: user
Password: demo123
Requested Role: ADMIN
```

The password is correct, but the backend knows that the account actually owns the `USER` role.

Detected event:

```text
Event: ROLE_MISMATCH
Actual Role: USER
Requested Role: ADMIN
Risk: HIGH
Action: LOGIN_DENIED
HTTP Status: 403
```

Example explanation:

```text
USER account attempted to authenticate using the ADMIN role.
```

---

### 4. Failed Authentication

Example:

```text
Username: user
Password: incorrect-password
Role: USER
```

Detected event:

```text
Event: FAILED_LOGIN
Risk: MEDIUM
Action: LOGIN_DENIED
HTTP Status: 401
```

Repeated failed authentication attempts are tracked.

---

### 5. Brute-Force Detection

Five consecutive failed USER authentication attempts trigger:

```text
Event: BRUTE_FORCE
Risk: HIGH
Failed Attempts: 5
Action: FLAGGED
```

Repeated authentication failures targeting a privileged ADMIN account are classified more severely:

```text
Event: BRUTE_FORCE
Risk: CRITICAL
Failed Attempts: 5
Action: FLAGGED
```

---

### 6. Unauthorized ADMIN Access

A logged-in USER manually requesting:

```text
/admin/users
```

is blocked automatically.

Detected event:

```text
Event: UNAUTHORIZED_ACCESS
Actual Role: USER
Endpoint: /admin/users
Risk: CRITICAL
Action: BLOCKED
HTTP Status: 403
```

The same protection applies to:

```text
/security-dashboard
```

for non-ADMIN users.

---

### 7. Suspicious Request Input

The request filter inspects query parameters for configured suspicious patterns.

If a request matches one of the educational detection rules:

```text
Event: SUSPICIOUS_INPUT
Risk: CRITICAL
Action: BLOCKED
HTTP Status: 400
```

> This rule-based detector is an educational demonstration and is not intended to replace parameterized queries, input validation, a Web Application Firewall, or other production security controls.

---

### 8. Rate Misuse

The application maintains a request counter for each detected client IP.

Configured demo threshold:

```text
30 monitored requests / 60 seconds
```

When the threshold is exceeded:

```text
Event: RATE_MISUSE
Risk: HIGH
Action: BLOCKED
HTTP Status: 429
```

The request count is calculated automatically by the backend rather than being manually entered.

---

## 📊 Live Security Dashboard

The ADMIN security dashboard is available at:

```text
/security-dashboard
```

It displays:

```text
Time
Client / IP
Actual and Requested Role
HTTP Request
Security Event
Risk
Action
HTTP Status
Explanation
```

Security events are streamed from Spring Boot to the browser using **Server-Sent Events (SSE)**.

```text
Threat Detected
      │
      ▼
SecurityEventService
      │
      ├──── Save to H2
      │
      └──── Push using SSE
                    │
                    ▼
            Dashboard updates
              immediately
```

No manual browser refresh or periodic polling is required.

---

## 🌐 Client IP Detection

The monitoring filter automatically reads the client address from the incoming request.

```java
request.getRemoteAddr();
```

For cleaner localhost demonstration output, IPv6 loopback values such as:

```text
::1
0:0:0:0:0:0:0:1
```

are normalized to:

```text
127.0.0.1
```

The localhost version intentionally does not blindly trust forwarded-IP headers.

---

## 📁 Project Structure

```text
src/main/java/com/apimisuseguard/
│
├── controller/
│   ├── EventStreamController.java
│   ├── LoginController.java
│   ├── MisuseController.java
│   └── DemoApiController.java
│
├── filter/
│   └── ApiMisuseFilter.java
│
├── model/
│   └── SecurityEvent.java
│
├── repository/
│   └── SecurityEventRepository.java
│
├── service/
│   ├── SecurityEventService.java
│   └── SecurityEventStreamService.java
│
└── ApiMisuseGuardApplication.java
```

Frontend:

```text
src/main/resources/templates/
│
├── login.html
├── profile.html
├── admin-dashboard.html
└── index.html
```

---

## ▶️ Running the Project Locally

### Requirements

```text
Java 21+
Maven
```

Clone the repository:

```bash
git clone https://github.com/Roshni1647/api-misuse-guard.git
```

Enter the project directory:

```bash
cd api-misuse-guard
```

On Windows:

```powershell
.\mvnw.cmd spring-boot:run
```

Or using Maven:

```bash
mvn spring-boot:run
```

Then open:

```text
http://localhost:8080/
```

---

## 🎥 Demo Strategy

For the demonstration video, two separate browser sessions can be used.

```text
Normal Chrome
     ↓
ADMIN login
     ↓
/security-dashboard
     ↓
Live monitoring window


Incognito Window
     ↓
USER / suspicious scenarios
     ↓
Events appear live on ADMIN dashboard
```

This demonstrates the monitoring system and the protected application simultaneously.

---

## 📸 Screenshots

Screenshots will demonstrate:

```text
Secure Login
USER Profile
ADMIN Dashboard
Live Security Monitor
Role Mismatch Detection
Brute-Force Detection
Unauthorized Access Detection
Rate Misuse Detection
```

---

## 🎬 Demo Video

**Demo video:** Coming soon

The demonstration will show normal authentication alongside automatically detected and explained security events.

---

## ⚠️ Scope and Limitations

This project is designed as a **defensive educational security-monitoring demonstration**.

It:

* monitors requests made to its own Spring Boot application
* does not scan external websites
* does not exploit third-party applications
* does not perform automated credential attacks against external systems
* uses simplified rule-based detection for demonstration
* currently uses an in-memory H2 database, so security-event history resets when the application restarts
* uses hard-coded local demo accounts rather than a production authentication database

A production implementation would typically add Spring Security, BCrypt password hashing, persistent PostgreSQL storage, distributed rate limiting, trusted-proxy configuration, structured auditing, and more advanced detection logic.

---

## 🎯 Key Learning Outcomes

This project demonstrates practical understanding of:

```text
Spring Boot MVC
HTTP Filters
Authentication Logic
Session Management
Role-Based Authorization
API Security Monitoring
Request Rate Tracking
JPA / Hibernate
Security Event Logging
Risk Classification
Explainable Detection
Server-Sent Events
Real-Time Dashboards
```

---

## 👩‍💻 Author

**Roshni**

Computer Science Engineering

---

## 📄 Disclaimer

API Misuse Guard is an educational defensive-security project intended for learning, demonstration, and localhost testing. It should only be used on applications and systems that you own or are explicitly authorized to test.
