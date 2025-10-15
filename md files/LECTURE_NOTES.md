# DevSecOps Lecture Demonstration Guide

## Lecture Outline (45-60 minutes)

### Part 1: Introduction (10 minutes)

#### What is DevSecOps?
- Traditional approach: Security as a gate at the end
- DevSecOps approach: Security integrated throughout
- Key principle: "Shift Left" - find and fix issues early

#### Why DevSecOps?
- Faster time to market with security built-in
- Reduced cost of fixing vulnerabilities
- Shared responsibility for security
- Compliance automation

#### Traditional vs DevSecOps Approach

```
TRADITIONAL WATERFALL SECURITY
────────────────────────────────────────────────────────────────
Plan → Design → Develop → Test → [SECURITY GATE] → Deploy
                                        ↑
                            Security team finds 100+ issues
                            Delays release by weeks/months
                            High cost to fix

DEVSECOPS APPROACH
────────────────────────────────────────────────────────────────
┌─────────────────── Continuous Security ───────────────────┐
│                                                            │
Plan → Design → Develop → Test → Deploy → Monitor
  ↓      ↓        ↓        ↓       ↓        ↓
Security Security Security Security Security Security
 Tools    Tools    Tools    Tools   Tools    Tools
  │        │        │        │       │        │
Threat  Security  SAST    Container WAF    Runtime
Model   Review   SCA      Scan            Protection
        IaC Scan  Secrets  DAST
                  Scan
```

#### The Cost of Fixing Vulnerabilities

```
┌──────────────────────────────────────────────────────────┐
│ Relative Cost to Fix Security Issues                     │
└──────────────────────────────────────────────────────────┘

Design Phase:        $    (1x)
Development:         $$   (6x)
Testing:            $$$   (15x)
Production:     $$$$$$$   (100x)

DevSecOps Goal: Find and fix issues in Design/Development phase!
```

### Part 2: Project Walkthrough (15 minutes)

#### Show the Application Structure
```
devsecops-demo/
├── app.py                 # Simple Flask application
├── test_app.py           # Unit tests
├── Dockerfile            # Container configuration
├── requirements.txt      # Dependencies
└── .github/workflows/    # CI/CD pipeline
```

#### Live Demo: Run the Application
```bash
# Activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements-dev.txt

# Run the app
python app.py

# Visit http://localhost:5000
```

**Discussion Point**: Show how simple applications still need security

#### DevSecOps Tools Ecosystem Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DEVSECOPS TOOLS LANDSCAPE                         │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   PLAN/DESIGN    │  │    DEVELOP       │  │   BUILD/TEST     │
├──────────────────┤  ├──────────────────┤  ├──────────────────┤
│ Threat Modeling  │  │ IDE Plugins      │  │ SAST             │
│ • OWASP Threat   │  │ • SonarLint      │  │ • Bandit         │
│   Dragon         │  │ • Snyk Code      │  │ • SonarQube      │
│ • Microsoft TMT  │  │ • GitHub Copilot │  │ • Semgrep        │
│                  │  │                  │  │ • CodeQL         │
│ Security Stories │  │ Pre-commit Hooks │  │                  │
│ • JIRA Security  │  │ • git-secrets    │  │ SCA              │
│ • Threat Cards   │  │ • detect-secrets │  │ • Safety         │
│                  │  │ • pre-commit     │  │ • Snyk Open Src  │
│ Design Review    │  │                  │  │ • Dependabot     │
│ • Confluence     │  │ Code Review      │  │ • WhiteSource    │
│ • Draw.io        │  │ • GitHub PR      │  │                  │
└──────────────────┘  │ • GitLab MR      │  │ Secrets Scan     │
                      │ • Gerrit         │  │ • GitLeaks       │
                      └──────────────────┘  │ • TruffleHog     │
                                            │ • git-secrets    │
                                            │                  │
                                            │ Unit Tests       │
                                            │ • pytest         │
                                            │ • JUnit          │
                                            │ • Jest           │
                                            └──────────────────┘
                                                     │
                                                     ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   CONTAINER      │  │    DEPLOY        │  │   OPERATE        │
├──────────────────┤  ├──────────────────┤  ├──────────────────┤
│ Image Scan       │  │ DAST             │  │ Monitoring       │
│ • Trivy          │  │ • OWASP ZAP      │  │ • Prometheus     │
│ • Clair          │  │ • Burp Suite     │  │ • Grafana        │
│ • Anchore        │  │ • Arachni        │  │ • Datadog        │
│ • Aqua           │  │                  │  │ • New Relic      │
│                  │  │ Pen Testing      │  │                  │
│ IaC Scan         │  │ • Metasploit     │  │ Logging          │
│ • Checkov        │  │ • Nmap           │  │ • ELK Stack      │
│ • tfsec          │  │ • Nessus         │  │ • Splunk         │
│ • Terrascan      │  │                  │  │ • Loki           │
│ • kube-bench     │  │ Compliance       │  │                  │
│                  │  │ • InSpec         │  │ SIEM             │
│ Dockerfile Lint  │  │ • OpenSCAP       │  │ • Wazuh          │
│ • hadolint       │  │ • Chef InSpec    │  │ • OSSEC          │
│                  │  │                  │  │ • Falco          │
│ Image Signing    │  │ Deployment       │  │                  │
│ • Notary         │  │ • ArgoCD         │  │ WAF              │
│ • Cosign         │  │ • Spinnaker      │  │ • ModSecurity    │
│                  │  │ • Flux           │  │ • AWS WAF        │
└──────────────────┘  └──────────────────┘  │ • Cloudflare     │
                                            │                  │
                                            │ Runtime Security │
                                            │ • Falco          │
                                            │ • Aqua Runtime   │
                                            │ • Sysdig         │
                                            └──────────────────┘
```

### Part 3: Security Scanning (15 minutes)

#### SAST - Static Application Security Testing

**Tool: Bandit**
```bash
bandit -r . -f txt
```

**What to show:**
- How it analyzes code without running it
- Types of issues it finds:
  - Hardcoded passwords
  - SQL injection risks
  - Use of insecure functions
  - Path traversal vulnerabilities

**Live Exercise**: Intentionally introduce a vulnerability
```python
# Add this to app.py temporarily to show Bandit catching it
import os
password = "hardcoded_password_123"  # B105: Hardcoded password
```

#### Dependency Scanning

**Tool: Safety**
```bash
safety check
```

**What to show:**
- Checks for known vulnerabilities in dependencies
- CVE (Common Vulnerabilities and Exposures) tracking
- Severity levels (LOW, MEDIUM, HIGH, CRITICAL)

**Discussion Point**: Even if your code is secure, dependencies might not be

#### Container Scanning

**Tool: Trivy**
```bash
docker build -t devsecops-demo .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image devsecops-demo:latest
```

**What to show:**
- OS package vulnerabilities
- Application dependency issues
- Configuration problems
- Security best practices violations

### Part 4: Automated Testing (10 minutes)

#### Unit Tests
```bash
pytest --cov=app --cov-report=term-missing
```

**What to show:**
- Test coverage metrics
- How tests verify functionality
- Security-related tests (input validation, error handling)

**Key Tests to Highlight:**
- `test_echo_endpoint_too_long`: Input validation
- `test_echo_endpoint_invalid_content_type`: Proper error handling

### Part 5: CI/CD Pipeline (10 minutes)

#### Pipeline Stages

Show [.github/workflows/devsecops-pipeline.yml](.github/workflows/devsecops-pipeline.yml):

1. **Security Scan Stage**
   - Runs before any code deployment
   - Fails fast if critical issues found
   - Generates security reports

2. **Test Stage**
   - Validates functionality
   - Measures code coverage
   - Ensures quality standards

3. **Build Stage**
   - Creates Docker image
   - Scans container for vulnerabilities
   - Tags for deployment

4. **Deploy Stage**
   - Only runs on main branch
   - Simulated in this demo
   - Would deploy to production

**Visual Aid**: Draw the pipeline on board
```
Code Push → Security Scan → Tests → Build → Container Scan → Deploy
     ↓            ↓           ↓        ↓          ↓            ↓
   [GIT]      [Bandit]    [pytest] [Docker]   [Trivy]    [Production]
              [Safety]
```

### Part 6: Container Security (10 minutes)

#### Dockerfile Security Features

Show [Dockerfile](Dockerfile) and explain:

1. **Multi-stage build**
   ```dockerfile
   FROM python:3.11-slim as builder
   # ... build steps ...
   FROM python:3.11-slim
   # ... final stage ...
   ```
   - Smaller final image
   - Build tools not in production image

2. **Non-root user**
   ```dockerfile
   RUN useradd -m -u 1000 appuser
   USER appuser
   ```
   - Principle of least privilege
   - Limits damage from container escape

3. **Health checks**
   ```dockerfile
   HEALTHCHECK --interval=30s --timeout=3s \
     CMD python -c "import urllib.request; ..."
   ```
   - Monitors application health
   - Enables auto-recovery

#### Docker Compose Security

Show [docker-compose.yml](docker-compose.yml):
- `no-new-privileges`: Prevents privilege escalation
- `cap_drop: ALL`: Removes all Linux capabilities
- `read_only: true`: Makes filesystem read-only

### Part 7: Interactive Discussion (5-10 minutes)

#### Questions to Ask Students

1. **When should security scanning happen?**
   - Answer: Throughout the pipeline, not just at the end

2. **What happens if a critical vulnerability is found?**
   - Answer: Pipeline should fail, preventing deployment

3. **Who is responsible for security in DevSecOps?**
   - Answer: Everyone on the team

4. **Why automate security checks?**
   - Answer: Consistency, speed, reduced human error

5. **What's the difference between SAST and DAST?**
   - SAST: Static (code analysis without running)
   - DAST: Dynamic (testing running application)

## Hands-On Exercises for Students

### Exercise 1: Find the Vulnerability (10 minutes)
Add a vulnerable code snippet and have students identify it:
```python
# Add to app.py
import subprocess
@app.route('/ping')
def ping():
    ip = request.args.get('ip')
    # Vulnerable to command injection!
    result = subprocess.run(f"ping -c 1 {ip}", shell=True)
    return str(result)
```

**Question**: What's wrong with this code?
**Answer**: Command injection vulnerability

### Exercise 2: Fix the Dockerfile (10 minutes)
Give students a poorly secured Dockerfile:
```dockerfile
FROM python:3.11
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```

**Question**: What security improvements can be made?
**Answers**:
- Use slim base image
- Add non-root user
- Multi-stage build
- Add health check
- Use .dockerignore

### Exercise 3: Write Security Tests (15 minutes)
Have students write tests for security scenarios:
- SQL injection prevention
- XSS prevention
- Authentication bypass attempts

## Key Takeaways

1. **Shift Left**: Integrate security early
2. **Automate Everything**: Security checks in pipeline
3. **Fast Feedback**: Fail fast on security issues
4. **Shared Responsibility**: Everyone owns security
5. **Continuous Improvement**: Update tools and practices

## Additional Resources for Students

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- DevSecOps Manifesto: https://www.devsecops.org/
- CIS Docker Benchmark: https://www.cisecurity.org/benchmark/docker
- NIST DevSecOps Guide: https://csrc.nist.gov/publications

## Common Questions & Answers

**Q: Doesn't security slow down development?**
A: Initially yes, but finding issues early is much faster than fixing them in production.

**Q: What if security scans have false positives?**
A: Configure tools appropriately and have a process to review and suppress false positives.

**Q: How do we handle security vs. speed tradeoffs?**
A: Use risk-based approach. Critical issues block deployment, lower severity issues tracked for later.

**Q: What about secrets in code?**
A: Never commit secrets. Use environment variables, secrets managers, or tools like git-secrets.

## Demonstration Tips

1. **Have backup**: Run everything locally before lecture
2. **Show failures**: Intentionally break things to show how pipeline catches issues
3. **Interactive**: Ask questions throughout, not just at the end
4. **Real examples**: Use examples from recent news (data breaches, vulnerabilities)
5. **Time management**: Keep demos short, focus on concepts

## Follow-up Assignment Ideas

1. Add more security tools (e.g., GitLeaks for secrets scanning)
2. Create security gates (fail on HIGH/CRITICAL findings)
3. Add DAST scanning with OWASP ZAP
4. Implement infrastructure scanning with Checkov
5. Create security dashboard with metrics

---

**Remember**: The goal is not to make students security experts, but to make them security-aware developers who integrate security into their daily work.
