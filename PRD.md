# Network Recon Web App

## Product Requirements Document (PRD)

### 1. Project Overview

**Project Name:** Network Recon

**Project Type:** Cybersecurity Reconnaissance Web Application

**Purpose:**
Network Recon is a Python-based web application designed for authorized reconnaissance of a user's own home or lab network. The application will identify active devices on the local network and collect basic reconnaissance information such as IP addresses, MAC addresses, hostnames, and selected common open ports.

The project is being developed for a cybersecurity penetration testing and ethical hacking course. The application is intended to demonstrate concepts associated with the reconnaissance phase of a penetration test while remaining non-intrusive.

The final application must be presented professionally through GitHub and include clear documentation explaining installation, functionality, operation, and step-by-step usage.

---

# 2. Primary Goal

Create a simple, professional, browser-based network reconnaissance tool capable of discovering and displaying useful information about devices on an authorized local network.

The application should make reconnaissance information easy to understand through a web interface rather than requiring users to interpret raw terminal output.

---

# 3. Target User

The primary user is a cybersecurity student or home-lab administrator who wants to perform basic reconnaissance against a network they own or have explicit authorization to assess.

The initial version is intended for:

* Home networks
* Cybersecurity labs
* Small test networks
* Classroom demonstrations
* Authorized security testing environments

---

# 4. Authorization and Ethical Scope

The application must clearly state that it is intended only for networks the user owns or has explicit permission to assess.

The application is not intended to:

* Scan arbitrary Internet targets
* Exploit vulnerabilities
* Attempt authentication
* Crack passwords
* Perform brute-force attacks
* Conduct denial-of-service testing
* Modify remote systems
* Install software on remote systems
* Evade security controls
* Perform intrusive vulnerability exploitation

The project should remain focused on reconnaissance.

---

# 5. Core Functional Requirements

## 5.1 Network Discovery

The application must identify active devices on the user's authorized local network.

The application should determine which hosts are currently visible or responsive.

Each discovered device should receive a result entry.

---

## 5.2 IP Address Collection

For each discovered device, the application should display its local IPv4 address when available.

Example sanitized output:

192.168.1.10

192.168.1.25

192.168.1.100

Actual home-network information must not be published to GitHub.

---

## 5.3 MAC Address Collection

When technically available from the local network, the application should identify and display the MAC address associated with a discovered device.

MAC address information must remain within the local application/results environment.

Real MAC addresses must not appear in:

* GitHub documentation
* Public screenshots
* README examples
* Source-code examples
* Assignment screenshots

Sanitized or fictional MAC addresses should be used for examples.

---

## 5.4 Hostname Collection

The application should attempt to identify a hostname for discovered devices when hostname information is available.

Examples of possible sanitized display names:

* desktop-lab
* ubuntu-test
* printer-demo
* server-example

Failure to resolve a hostname must not cause a scan to fail.

Devices without a known hostname may display:

Unknown

or:

Not Available

---

# 6. Common Port Checks

The application should check a limited selection of commonly used TCP ports.

This feature is intended for basic service reconnaissance and must not become an exhaustive or aggressive port scanner.

Example ports may include services commonly associated with:

* SSH
* HTTP
* HTTPS
* DNS
* SMB
* RDP
* FTP

Port checks should use conservative connection timeouts to prevent scans from becoming unnecessarily slow.

The initial version should not scan all 65,535 TCP ports.

---

# 7. Recon Results

For each discovered device, the web interface should present information in a clear format.

Recommended fields:

| Field             | Description                           |
| ----------------- | ------------------------------------- |
| IP Address        | Local IPv4 address                    |
| Hostname          | Resolved hostname when available      |
| MAC Address       | Local hardware address when available |
| Status            | Visible/active status                 |
| Open Common Ports | Selected responsive TCP ports         |
| Scan Time         | Time the host was observed            |

Results should be easily understandable by someone viewing the application for the first time.

---

# 8. Web Application Requirements

The project must operate as a web application.

The recommended MVP architecture is:

Python
Flask
HTML
CSS

A large JavaScript frontend framework is not required for the initial version.

The goal is simplicity, maintainability, and presentation quality.

---

# 9. Main Web Interface

The primary page should include:

* Application name
* Short explanation of the tool
* Authorization/ethical-use notice
* Scan button
* Scan status
* Results area
* Clearly labeled device information

The interface should look professional enough to be included in the assignment screenshot and GitHub repository.

---

# 10. Scan Workflow

The expected user workflow should be approximately:

1. User launches the web application.
2. User opens the application in a browser.
3. Application displays the reconnaissance dashboard.
4. User confirms they are scanning an authorized network.
5. User starts a reconnaissance scan.
6. Application determines the appropriate local network range.
7. Application discovers responsive devices.
8. Application gathers IP addresses.
9. Application attempts MAC address identification.
10. Application attempts hostname resolution.
11. Application checks selected common ports.
12. Application processes the results.
13. Results appear in the browser.
14. Optional local report output may be generated.

---

# 11. Privacy Requirements

Actual reconnaissance data is considered private infrastructure information.

The following real information must not be intentionally uploaded to GitHub:

* Home IP inventory
* MAC addresses
* Device hostnames
* Open-port inventories
* Raw scan reports
* Authentication credentials
* API keys
* Tokens
* Environment secrets

Local reports should remain within the existing:

reports/

directory.

The existing `.gitignore` configuration should continue preventing generated report files from being tracked by Git.

Before every major GitHub push involving scan functionality, `git status` should be reviewed to ensure private scan results are not staged.

---

# 12. Screenshot Privacy

The professor requires a screenshot of the web application.

The screenshot used for submission should contain:

* Sanitized results
* Demonstration data
* Fictional device names
* Example IP addresses
* Example MAC addresses

The screenshot should not expose the actual inventory of the user's home network.

---

# 13. Reporting

The application may provide local reports summarizing reconnaissance results.

Possible report information:

* Scan date/time
* Number of discovered devices
* Device IP addresses
* Hostnames
* MAC addresses
* Common open ports

Reports should remain local by default.

Generated reports must not automatically be committed to GitHub.

---

# 14. Error Handling

The application should handle common failures gracefully.

Examples include:

* Hostname cannot be resolved
* MAC address is unavailable
* Host becomes unreachable during scan
* Port connection times out
* Network cannot be determined
* Application lacks required permission
* Invalid or unexpected network response

Errors should produce understandable messages rather than Python tracebacks being displayed directly to normal users.

---

# 15. Security Requirements

The application should follow basic secure-development practices.

Requirements include:

* No hard-coded passwords
* No hard-coded API keys
* No hard-coded bot tokens
* No credentials stored in Git
* Validate user-controlled inputs
* Avoid command injection
* Avoid unnecessary shell execution
* Use conservative scanning behavior
* Do not automatically elevate privileges
* Do not expose Flask debug mode publicly
* Do not make the application publicly Internet-accessible by default
* Keep reconnaissance within authorized local/private networks for the MVP

---

# 16. Local Network Restriction

Version 1 should focus on private/local IPv4 network ranges.

The application should not be designed as a public Internet scanning platform.

If target selection is introduced, it should be constrained or validated so accidental Internet-wide scanning is avoided.

---

# 17. Non-Intrusive Design

The application should prioritize low-impact reconnaissance.

The MVP should avoid:

* Vulnerability exploitation
* Credential attacks
* Aggressive service enumeration
* Large-scale scanning
* Packet flooding
* Denial-of-service behavior
* Persistence
* Malware functionality
* Security-control bypassing

The objective is discovery and identification, not exploitation.

---

# 18. Existing Project Structure

The existing project structure should remain in place.

network-recon/

README.md

.gitignore

src/

tests/

reports/

The project should continue building within this established structure rather than reorganizing the repository unnecessarily.

---

# 19. Python Environment

Development must use the existing Conda environment:

network-recon

with:

Python 3.11

Developers should activate the environment before running or installing project dependencies.

Example:

conda activate network-recon

---

# 20. Dependency Management

Python dependencies required by the application should eventually be documented in:

requirements.txt

Only dependencies that are actually needed by the application should be included.

Avoid unnecessary packages.

---

# 21. Testing Requirements

Testing should cover major application functionality where practical.

Important areas include:

* Network-range handling
* Host discovery logic
* Hostname resolution
* MAC address processing
* Port-check logic
* Invalid responses
* Empty scan results
* Web application routes
* Data formatting

AI-generated code should not be considered complete simply because it runs once.

---

# 22. Git Requirements

Git should be used throughout development.

Development workflow:

1. Make a scoped change.
2. Review the changed files.
3. Run tests.
4. Run `git diff`.
5. Review the implementation.
6. Stage approved changes.
7. Commit with a descriptive message.
8. Push to GitHub.

Example commit messages:

* Add Flask application skeleton
* Add local host discovery
* Add hostname resolution
* Add common port checks
* Add reconnaissance dashboard
* Add test coverage
* Improve README installation guide
* Add sanitized project screenshot

---

# 23. AI-Assisted Development Workflow

The project will use multiple AI systems as development assistants.

## ChatGPT

Primary responsibilities:

* Requirements analysis
* PRD development
* Architecture recommendations
* Security review
* Code review
* Identifying bugs or unnecessary complexity
* Reviewing implementation against requirements
* Documentation recommendations

## Claude

Primary responsibilities:

* VibeCoding inside VS Code
* Reading the repository
* Creating implementation plans
* Writing application code
* Implementing requested changes
* Refactoring approved code
* Running development commands and tests when appropriate

Recommended workflow:

ChatGPT planning
→ PRD
→ Claude implementation plan
→ Claude code
→ User testing
→ Git diff
→ ChatGPT review
→ Claude revisions
→ Testing
→ Git commit
→ GitHub

Claude should implement one milestone at a time rather than attempting the entire application in a single operation.

---

# 24. Implementation Milestones

## Milestone 1 — Web Application Skeleton

Create the minimum Flask application necessary to:

* Start successfully
* Serve a browser page
* Display application branding
* Display authorization notice
* Provide placeholder scan functionality

No network scanning should be implemented yet.

---

## Milestone 2 — Local Host Discovery

Implement conservative discovery of devices on the authorized local network.

Requirements:

* Determine appropriate local network scope
* Discover visible devices
* Return structured results
* Handle unreachable devices gracefully

---

## Milestone 3 — Device Information

Add collection of:

* IP address
* MAC address where available
* Hostname where available

Missing information should not cause scan failure.

---

## Milestone 4 — Common Port Checks

Implement checks for a small, documented set of commonly used TCP ports.

Requirements:

* Conservative timeout
* Limited port list
* No exhaustive scanning
* Clear service/port presentation

---

## Milestone 5 — Web Dashboard

Display reconnaissance results professionally through the web interface.

Requirements:

* Organized device table/cards
* Clear field labels
* Scan progress/status
* User-friendly error messages

---

## Milestone 6 — Local Reporting

Provide optional local report generation.

Reports should remain inside the existing `reports/` area and remain excluded from Git tracking.

---

## Milestone 7 — Testing and Security Review

Perform:

* Functional testing
* Input validation review
* Error-handling review
* Privacy review
* Git review
* AI-generated code review

Run `git diff` and use ChatGPT as a secondary reviewer before approving major changes.

---

## Milestone 8 — Documentation and UI Polish

Improve:

* README
* Installation documentation
* Usage instructions
* Application explanation
* Troubleshooting
* Security/authorization statement
* User interface appearance

---

## Milestone 9 — Final Submission

Complete:

* Final testing
* Clean Git status
* Final GitHub push
* Sanitized screenshot
* Professional README
* GitHub repository link
* Assignment submission

---

# 25. README Requirements

The final README should include at minimum:

## Project Overview

What Network Recon is and why it was created.

## Features

What the application can do.

## Requirements

Required operating system/software/Python environment.

## Installation

Step-by-step installation instructions.

## Running the Application

Exact commands required to start the application.

## How It Works

High-level explanation of:

* Device discovery
* IP collection
* MAC identification
* Hostname resolution
* Port checks

## Usage Instructions

Step-by-step instructions for running a scan.

## Screenshot

A sanitized screenshot of the application.

## Privacy

Explain that real reconnaissance results remain local.

## Ethical Use

State that the tool is intended only for authorized networks.

## Limitations

Explain known MVP limitations.

---

# 26. Acceptance Criteria

The project is considered complete when:

* The web application launches successfully.
* A user can access the application from a browser.
* A user can initiate authorized local reconnaissance.
* The application identifies visible devices.
* IP addresses are displayed.
* MAC addresses are displayed when available.
* Hostnames are displayed when available.
* Selected common ports can be checked.
* Results display through the web interface.
* Missing device information does not crash the application.
* Private scan output is not pushed to GitHub.
* Real home-network information does not appear in screenshots.
* The README explains installation.
* The README explains what the tool does.
* The README explains how the tool works.
* The README contains step-by-step usage instructions.
* The repository looks professional.
* The assignment screenshot uses sanitized data.
* The GitHub repository link is ready for submission.

---

# 27. Definition of Done

Network Recon is considered finished when another person with the appropriate environment could:

1. Open the GitHub repository.
2. Understand what the project does.
3. Follow the installation instructions.
4. Start the application.
5. Open the web interface.
6. Understand how to use it.
7. Perform reconnaissance on an authorized local network.
8. Understand the results.
9. Review a professional project presentation without seeing private information from the developer's real home network.
