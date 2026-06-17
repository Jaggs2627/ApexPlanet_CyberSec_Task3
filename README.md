## Step 1: SQL Injection (SQLi) Risk Analysis & Remediation

### 1. Exploitation Summary
* **Vulnerability Description:** The application suffers from an unvalidated input vulnerability within the 'User ID' inquiry parameter, allowing database code injection.
* **Payload Used:** `%' UNION SELECT null, concat(user,':',password) FROM users #`
* **Impact:** By prematurely breaking out of the input delimiter (`%`), a malicious `UNION SELECT` statement was appended. This commanded the backend database engine to bypass application access controls and dump all administrative database contents, exposing critical authentication records (usernames and MD5 password hashes).

### 2. Remediation: Prevention via Prepared Statements
To eliminate SQL injection entirely, the application must completely separate user data from the database query logic using **Prepared Statements (Parameterized Queries)**.

#### Vulnerable Code (Low Security Context):

$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

$stmt = $mysqli->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->bind_param("s", $id);
$stmt->execute();
$result = $stmt->get_result();

---

## Step 2: Cross-Site Scripting (XSS) Analysis & Remediation

### 1. Exploitation Summary
* **Reflected XSS:** Transmitted via inputs that are immediately returned by the application context (such as URL parameters). 
* **Stored XSS:** Achieved by injecting a payload that persists inside the application database.
* **Payload Used (Stored):** `<svg onload=alert(1)>`
* **Impact:** Because the application does not validate, sanitize, or escape incoming user submissions, malicious scripts can be permanently injected into web fields (like a comment forum or guestbook). When an unsuspecting user visits the page, their browser pulls the script from the database and executes it contextually, potentially allowing cookie theft, session hijacking, or defacement.

### 2. Remediation & Mitigation Strategies
To eliminate Cross-Site Scripting comprehensively, multiple layers of defensive programming must be applied:

#### A. Output Encoding (Context-Aware Escaping)
All user-supplied text strings must be converted into safe literal string sequences before being rendered in HTML contexts. This converts special syntax elements into harmless text equivalents.
* **Vulnerable Input:** `<script>`
* **Secure Encoded Text:** `&lt;script&gt;`

In PHP, this is easily enforced using native functions like `htmlspecialchars()`:

echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
Content-Security-Policy: default-src 'self'; script-src 'self';

---
