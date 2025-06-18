## 📁 `log_parser.py` – *The Extractor*

**Purpose**: Read raw log lines and convert them into structured, usable data.

### ✅ Core Functionality:

* `parse_log_line(line: str) -> dict | None`

  * Uses regex to extract:

    * IP address
    * Timestamp
    * HTTP method (GET, POST, etc.)
    * Request path
    * HTTP status code
    * Response size
* Optional:

  * Convert timestamp to `datetime` object
  * Return `None` if the line doesn’t match the pattern (invalid or malformed)
* Optional helper functions:

  * `normalise_timestamp()`
  * `is_valid_log_line()`

---

## 🕵️ `suspicious_detector.py` – *The Inspector*

**Purpose**: Look at parsed log data and spot suspicious behaviour or patterns.

### ✅ Core Functionality:

* `detect_suspicious_activity(parsed_data: dict) -> str | None`

  * Analyses one parsed line (or uses memory of past lines) and returns an alert message if suspicious.

### 🔍 Possible Detection Features:

* **Brute-force login attempts**:

  * Multiple 403s or 401s from the same IP
* **Path probing**:

  * Accessing sensitive paths like `/admin`, `/etc/passwd`, `/wp-login.php`
* **Rate limiting**:

  * Too many requests in a short time from the same IP
* **Unusual status codes**:

  * Frequent 5xx (server errors), or rare combinations
* Optional:

  * IP-based tracking: count how many suspicious events an IP has had
  * Add a config or threshold system (`MAX_FAILED_ATTEMPTS = 5`)