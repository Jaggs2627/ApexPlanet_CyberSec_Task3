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

## Step 3: Cross-Site Request Forgery (CSRF) Analysis & Remediation

### 1. Exploitation Summary
* **Vulnerability Description:** The application's password update form uses predictable parameters passed through standard HTTP GET requests without implementing state-verification mechanics.
* **Payload Used:** `http://127.0.0.1/vulnerabilities/csrf/?password_new=password123&password_conf=password123&Change=Change`
* **Impact:** Because the application trusts any request matching this template format, an external attacker can host an invisible hyperlink or malicious image parameter (e.g., `<img src="..." width="0" height="0">`) on a completely unrelated website. If an authenticated user clicks the link or visits that malicious site while logged into this application, their browser will silently authorize the state-changing request, resetting their credentials completely without their active knowledge.

### 2. Remediation & Defense in Depth
To mitigate Cross-Site Request Forgery thoroughly, the application architecture must enforce strict cryptographic context validations:

#### A. Anti-CSRF Tokens (Synchronizer Token Pattern)
The application should generate a secure, unique, and cryptographically random string token inside the user's active session array whenever a state-changing form is generated. This value must be verified upon submission:

// On form generation: Assign a session validation token

$_SESSION['token'] = bin2hex(random_bytes(32));

// In the HTML form payload: Append a hidden token attribute

echo '<input type="hidden" name="user_token" value="'.$_SESSION['token'].'">';

// On processing submission: Enforce exact string verification

if (!hash_equals($_SESSION['token'], $_POST['user_token'])) {
    die("CSRF Token validation failure. Request terminated.");
}

---

## Step 4: Authentication Brute Force Analysis & Remediation

### 1. Exploitation Summary
* **Vulnerability Description:** The administrative login gateway lacks defensive rate-limiting mechanisms, concurrent connection throttling, or account lockout policies. This allows attackers to perform high-velocity dictionary authentication matching.
* **Tool & Wordlist Used:** `Hydra` with the `/usr/share/wordlists/fasttrack.txt` vocabulary profile.
* **Cracked Credentials Discovered:** `admin` : `password123`
* **Impact:** An external adversary can automate custom login generation loops to exhaust potential password variations. Upon mapping a working credential set, the attacker gains full authenticated administrative dominion over the underlying web portal.

### 2. Remediation & Defense Framework
To permanently shield authentication entry points from brute-force scripts, the following programming layers must be enforced:

#### A. Account Lockout Policies & Rate Limiting
Implement a backend database counter track that temporarily freezes an account alias or blocks an incoming IP address after a set number of consecutive failed authentication submissions (e.g., 5 failed attempts locks the route for 15 minutes).

#### B. Implementation of CAPTCHA CAPTCHA
Force a cryptographic human-verification challenge puzzle (such as Google reCAPTCHA) after 3 sequential authentication validation failures. This completely stops automated engines like Hydra by requiring human interactive validation to post requests.

#### C. Secure Password Hashing Configurations
Ensure all target password databases never store plaintext credentials. Upgrade database security maps to utilize adaptive, computationally intensive cryptographic hashing parameters like **Bcrypt** or **Argon2id**:

// Creating a high-security cryptographic representation

$secureHash = password_hash($userPassword, PASSWORD_ARGON2ID);

// Validating incoming attempts safely

if (password_verify($inputPassword, $secureHash)) {
    // Session authorized
}

---

## Step 5: File Inclusion (LFI) Analysis & Remediation

### 1. Exploitation Summary
* **Vulnerability Description:** The application's input parameter accepts direct file path requests dynamically without validating, white-listing, or sanitizing the structural directory target path context.
* **Payload Used:** `http://127.0.0.1/vulnerabilities/fi/?page=../../../../../../etc/passwd`
* **Impact:** By utilizing structured directory traversal sequences (`../`), an unprivileged attacker can break out of the intended web root storage matrix. This permits unauthorized execution or read access to sensitive administrative operating system infrastructure files (such as `/etc/passwd`), entirely breaking target confidentiality layers.

### 2. Remediation & Defense Roadmap
To comprehensively mitigate local and remote file inclusion pathways, the best architectural defense is to avoid dynamic user-supplied string path assignments entirely.

#### A. Implementation of a Strict Whitelist Array
If specific pages must be loaded dynamically via parameters, map them inside a locked, non-negotiable hardcoded whitelist array map index:

```php
$allowed_pages = [
    "include.php" => "include.php",
    "file1.php"    => "file1.php",
    "file2.php"    => "file2.php"
];

$page = $_GET['page'];

if (!array_key_exists($page, $allowed_pages)) {
    die("Error: Requested resource block is unauthorized.");
}

include($allowed_pages[$page]);

allow_url_fopen = Off
allow_url_include = Off
