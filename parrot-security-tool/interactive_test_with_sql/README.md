Available Options

1. configure
    all: Run all tests (network, vulnerability, exploitation, anonymity, auditing).
    network: Network scans (Nmap, Masscan, Netcat).
    vulnerability: Vulnerability scans (Nikto, SQLmap).
    exploitation: Exploitation attempts (Metasploit, John the Ripper).
    anonymity: Anonymity checks (AnonSurf, Tor).
    auditing: System auditing (Lynis, chkrootkit, system info).

2. targets
    Select target(s) for testing (single IP, file with IPs, or LAN scan).

3. run
    Execute the tests based on the configured profile and selected targets.
    Results are stored in the database and saved as reports.

4. export
    Export test results in selected formats (text, HTML, CSV).
    HTML reports include a filter to search by IP and color-coded vulnerability severity (red: ≥7.0, orange: ≥4.0, green: <4.0).

5. query_db
    Query the database for historical data (targets, test results, vulnerabilities).
    Supports filtering by IP and minimum CVSS score for vulnerabilities.

6. configure_automation
    Set up periodic data collection (simulated scans) and automatic HTML report generation.
    Scans will run every 30 minutes (1800 seconds), storing results in the database and generating HTML reports.

7. exit
    Exit the tool, closing the database connection and stopping anonymity services (e.g., Tor, AnonSurf).