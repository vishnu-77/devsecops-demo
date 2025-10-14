# Quick Start Guide - DevSecOps Demo

## 🚀 For Lecture Demonstration

### Repository
**GitHub**: https://github.com/vishnu-77/devsecops-demo

### What You Need
- Python 3.11+
- Git
- Docker (optional, for container demo)

---

## 📋 Quick Demo Steps

### 1. Clone the Repository
```bash
git clone https://github.com/vishnu-77/devsecops-demo.git
cd devsecops-demo
```

### 2. Set Up Environment
```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements-dev.txt
pip install pbr
```

### 3. Run Security Scans

**Bandit (SAST) - Static Code Analysis**
```bash
bandit -r app.py test_app.py -f txt
```
**Expected**: Finds 1 medium + 12 low severity issues

**Safety (SCA) - Dependency Vulnerability Scan**
```bash
safety check
```
**Expected**: Finds 5 vulnerabilities in dependencies

### 4. Run Tests
```bash
pytest --cov=app --cov-report=term-missing -v
```
**Expected**: All 6 tests pass, 83% coverage

### 5. Run the Application
```bash
python app.py
```
Visit: http://localhost:5000

**Test Endpoints:**
```bash
# Health check
curl http://localhost:5000/health

# Echo API
curl -X POST http://localhost:5000/api/echo \
  -H "Content-Type: application/json" \
  -d '{"message":"Hello DevSecOps!"}'
```

### 6. Docker Demo (Optional)
```bash
# Build image
docker build -t devsecops-demo .

# Run container
docker run -p 5000:5000 devsecops-demo

# Or use docker-compose
docker-compose up
```

---

## 📊 What to Show in Lecture

### 1. **Traditional vs DevSecOps** (5 min)
- Show diagram in README.md
- Explain "Shift Left" concept
- Discuss cost of fixing vulnerabilities

### 2. **Live Security Scanning** (10 min)
- Run Bandit, explain findings
- Run Safety, show CVE vulnerabilities
- Discuss false positives vs real issues

### 3. **Pipeline Walkthrough** (10 min)
- Open `.github/workflows/devsecops-pipeline.yml`
- Show 4 stages: Security → Test → Build → Deploy
- Explain security gates
- Show GitHub Actions tab (if available)

### 4. **Tools Comparison** (10 min)
- Show tool comparison tables in README.md
- Discuss SAST vs DAST vs SCA
- Show DevSecOps tools ecosystem map

### 5. **Container Security** (10 min)
- Show Dockerfile security features:
  - Multi-stage build
  - Non-root user
  - Health checks
- Explain docker-compose security settings

### 6. **Interactive Discussion** (10 min)
- Use questions from LECTURE_NOTES.md
- Discuss real-world scenarios
- Q&A

---

## 🎯 Key Demo Points

### Security Findings to Highlight:

**Bandit Finding:**
```
B104: Hardcoded bind all interfaces (0.0.0.0)
Location: app.py:78
```
**Discussion**: Why is this flagged? When is it actually a problem?

**Safety Findings:**
- Werkzeug CVE-2024-34069, CVE-2024-49766, CVE-2024-49767
- **Discussion**: What to do when dependencies have vulnerabilities?

### Code Examples to Show:

**Good: Input Validation** (app.py:45-48)
```python
message = data.get('message', '')
if len(message) > 1000:
    return jsonify({'error': 'Message too long'}), 400
```

**Good: Environment-based Debug** (app.py:77-78)
```python
debug = os.environ.get('FLASK_ENV') == 'development'
app.run(host='0.0.0.0', port=port, debug=debug)
```

---

## 📚 Documentation Files

| File | Purpose |
|------|---------|
| **README.md** | Architecture diagrams, tool comparisons, quick start |
| **LECTURE_NOTES.md** | Complete lecture guide with timing and exercises |
| **PIPELINE_GUIDE.md** | Detailed pipeline implementation guide |
| **QUICK_START.md** | This file - quick reference for demos |

---

## 🐛 Troubleshooting

### Issue: Bandit fails with "No module named 'pbr'"
**Solution**: `pip install pbr`

### Issue: Safety takes too long
**Solution**: This is normal on first run, uses online database

### Issue: Tests fail
**Solution**: Make sure you're in the project directory and venv is activated

### Issue: Port 5000 already in use
**Solution**:
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:5000 | xargs kill
```

---

## 💡 Interactive Exercises

### Exercise 1: Add a Vulnerability
Add this to app.py and run Bandit:
```python
import pickle
password = "hardcoded123"  # Bandit will flag this
```

### Exercise 2: Fix a Security Issue
Challenge students to fix the B104 finding (binding to all interfaces)

### Exercise 3: Add a Test
Have students write a test for SQL injection protection

---

## 🔗 Quick Links

- **GitHub Repo**: https://github.com/vishnu-77/devsecops-demo
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **DevSecOps Manifesto**: https://www.devsecops.org/
- **Bandit Docs**: https://bandit.readthedocs.io/
- **Safety DB**: https://data.safetycli.com/

---

## ✅ Pre-Lecture Checklist

- [ ] Clone repository
- [ ] Test all commands work
- [ ] Ensure internet connection (for Safety)
- [ ] Have Docker running (if doing container demo)
- [ ] Open key files in IDE beforehand
- [ ] Test http://localhost:5000 accessibility
- [ ] Prepare GitHub Actions tab in browser
- [ ] Review LECTURE_NOTES.md

---

## 📞 Support

If you encounter issues during the lecture:
1. Check LECTURE_NOTES.md for detailed guidance
2. Refer to troubleshooting section above
3. Fall back to showing diagrams and discussing concepts

**Remember**: The goal is to teach concepts, not perfect execution. Security findings and even errors can be great teaching moments!

---

**Good luck with your lecture!** 🎓
