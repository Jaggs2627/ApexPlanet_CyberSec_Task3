## Step 1: SQL Injection (SQLi) Risk Analysis & Remediation

### 1. Exploitation Summary
* **Vulnerability Description:** The application suffers from an unvalidated input vulnerability within the 'User ID' inquiry parameter, allowing database code injection.
* **Payload Used:** `%' UNION SELECT null, concat(user,':',password) FROM users #`
* **Impact:** By prematurely breaking out of the input delimiter (`%`), a malicious `UNION SELECT` statement was appended. This commanded the backend database engine to bypass application access controls and dump all administrative database contents, exposing critical authentication records (usernames and MD5 password hashes).

### 2. Remediation: Prevention via Prepared Statements
To eliminate SQL injection entirely, the application must completely separate user data from the database query logic using **Prepared Statements (Parameterized Queries)**.

#### Vulnerable Code (Low Security Context):
```php
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);```

#### Secure Code:
```php
$stmt = $mysqli->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->bind_param("s", $id);
$stmt->execute();
$result = $stmt->get_result();
