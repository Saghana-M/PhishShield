# PhishShield – Phishing URL Risk Detection System

A lightweight, robust college academic project combining **Java Object-Oriented Programming (OOP)** and **Database Management Systems (DBMS)** to detect potentially suspicious URLs using rule-based heuristic analysis.

---

## 1. Project Overview

PhishShield allows users to submit suspected URLs received through emails, text messages, or chat applications. The system evaluates the URL text against predefined structural detection rules, computes a composite risk score (0–100), categorizes the risk level, and stores scan events and identified findings into a MySQL 8 database.

### Core Principles
- **Text-Only Heuristic Analysis:** PhishShield analyzes lexical and syntactic URL properties only. It **never visits, executes, or downloads content** from submitted URLs.
- **Rule-Based Engine:** Transparent, deterministic scoring engine implemented natively in Java.
- **Persistent DBMS History:** Every scan is recorded with foreign keys linking to detected findings and cumulative URL statistics.

---

## 2. Technology Stack

- **Backend:** Java 17+, Spring Boot 3.3.4 (Spring Web, Spring JDBC `JdbcTemplate`, Validation)
- **Frontend:** HTML5, CSS3, Vanilla JavaScript (Modern, minimalist cybersecurity theme)
- **Database:** MySQL 8 (`phishshield_db`)
- **Build Tool:** Apache Maven
- **Protocol:** REST API, JSON

---

## 3. Java OOP Architecture

PhishShield strictly showcases the core pillars of Object-Oriented Programming:

| OOP Concept | Implementation in PhishShield |
|---|---|
| **Encapsulation** | `URL.java`, `Scan.java`, `Finding.java`, and `UrlMaster.java` keep state strictly `private`, exposing controlled access via validated constructors, getters, and setters. |
| **Abstraction** | `DetectionRule.java` (Interface) defines the analysis contract (`evaluate(URL)`). `BaseDetectionRule.java` (Abstract class) provides common attributes and helper methods. |
| **Inheritance** | Concrete detection rules (`LongURLRule`, `IPAddressRule`, `SuspiciousKeywordRule`, `SubdomainRule`, `URLStructureRule`) extend `BaseDetectionRule`. |
| **Polymorphism** | `URLAnalyzer.java` maintains a polymorphic collection (`List<DetectionRule>`) and dynamically evaluates each rule using uniform interface dispatch. |
| **Exception Handling** | Custom exceptions (`InvalidUrlException`, `DatabaseOperationException`, `UrlNotFoundException`) handled by `@RestControllerAdvice` (`GlobalExceptionHandler.java`). |
| **Collections Framework** | `ArrayList`, `LinkedHashSet`, `Set`, and `Map` used across detection and repository layers. |

---

## 4. Detection Rules & Risk Scoring

PhishShield evaluates five weighted structural warning signs:

| Detection Rule | Risk Points | Detection Criteria |
|---|:---:|---|
| **Unusually Long URL** | **+10** | URL length > 75 characters (common obfuscation tactic). |
| **IP Address as Hostname** | **+25** | Host is an IPv4 or IPv6 address instead of a registered domain. |
| **Suspicious Keyword Combinations** | **+10** | Contains multiple credential/action keywords (`login`, `verify`, `account`, `banking`, `security`) or high-target brands (`paypal`, `apple`, `chase`) paired with action tokens. |
| **Unusual Subdomain Structure** | **+15** | Deep subdomain nesting (>2 dots) or reputable brand names embedded in subdomains (e.g., `paypal.com.phishingsite.net`). |
| **Misleading URL Structure** | **+20** | Deceptive syntax: `@` symbol in URL, non-standard ports (e.g. `:8080`, `:8443`), excessive hyphens, or double slashes `//` in paths. |

### Prototype Heuristic Thresholds:
- **0 – 19: Low Risk** (Green) – Few or no indicators detected. Normal caution advised.
- **20 – 49: Suspicious** (Amber) – Multiple warning indicators triggered. Exercise caution.
- **50 – 100: High Risk** (Red) – Severe phishing indicators. Do not click or input credentials.

---

## 5. MySQL Database Design (`phishshield_db`)

The database consists of three related tables enforcing 3NF and referential integrity:

```
+-----------------------------------+
|            URL_MASTER             |
+-----------------------------------+
| PK  url_id                        |
|     original_url                  |
| UQ  normalized_url                |
|     latest_score                  |
|     latest_status                 |
|     first_seen                    |
|     last_seen                     |
|     total_scans                   |
+-----------------------------------+
                  | 1
                  |
                  | N
+-----------------------------------+
|           SCAN_HISTORY            |
+-----------------------------------+
| PK  scan_id                       |
| FK  url_id                        |-------> URL_MASTER(url_id)
|     scanned_url                   |
|     scan_score                    |
|     scan_status                   |
|     scanned_at                    |
+-----------------------------------+
                  | 1
                  |
                  | N
+-----------------------------------+
|           SCAN_FINDINGS           |
+-----------------------------------+
| PK  finding_id                    |
| FK  scan_id                       |-------> SCAN_HISTORY(scan_id)
|     rule_name                     |
|     points                        |
|     explanation                   |
+-----------------------------------+
```

### Key DBMS Features Implemented
- **Primary & Foreign Keys:** Cascading deletes ensure referential integrity.
- **Unique Constraint:** `normalized_url` prevents duplicate URL entity rows.
- **Transactions:** `@Transactional` guarantees atomicity across the three tables during scans.
- **Complex Queries:** Parameterized SQL queries, `JOIN` queries between `SCAN_HISTORY` and `URL_MASTER`, `COUNT` aggregates, and `GROUP BY` status analytics.

---

## 6. REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Analyzes a submitted URL, persists scan & findings, returns results with prior scan info. |
| `GET` | `/api/history` | Retrieves list of recent scans (joined with URL statistics). |
| `GET` | `/api/history/{scanId}` | Retrieves complete details and warning findings for an individual scan. |
| `GET` | `/api/url/{urlId}/history` | Retrieves all historical scan events for a particular URL. |
| `GET` | `/api/stats` | Returns aggregate counts and risk distribution metrics. |

---

## 7. Setup & Execution Instructions

### Prerequisites
1. **Java Development Kit (JDK 17 or higher):** `java -version`
2. **Apache Maven:** `mvn -v`
3. **MySQL Server 8.0:** Running on `localhost:3306`

### Database Setup
1. Log into your MySQL console or Workbench:
   ```bash
   mysql -u root -p
   ```
2. Execute the `schema.sql` file located in the project root:
   ```sql
   source /path/to/PhishShield/schema.sql;
   ```
   *(Or let Spring Boot automatically create the schema on startup as configured in `application.properties`).*

3. Configure your MySQL credentials in `src/main/resources/application.properties`:
   ```properties
   spring.datasource.url=jdbc:mysql://localhost:3306/phishshield_db?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC
   spring.datasource.username=YOUR_MYSQL_USERNAME
   spring.datasource.password=YOUR_MYSQL_PASSWORD
   ```

### Running the Application
From the project root:
```bash
mvn spring-boot:run
```

Open your web browser and navigate to:
```
http://localhost:8080
```

---