# OSINT-Driven Adversarial Attacks on Misconfigured ML Systems

⚠️ **WARNING: FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY**

This project demonstrates how Open Source Intelligence (OSINT) techniques can be used to discover and exploit misconfigured machine learning systems, and how to defend against such attacks.

## 🎯 Purpose

This demonstration is designed for:
- **Educational purposes** in security research and ML security courses
- **Defensive security analysis** to understand attack vectors
- **Security awareness** for ML practitioners and organizations
- **Testing on systems you OWN** or have explicit permission to test

**DO NOT** use this for unauthorized access, malicious attacks, or any illegal activities.

## 🏗️ Architecture

```
ml_osint_security/
├── vulnerable_system/     # Intentionally vulnerable ML system
│   ├── model_trainer.py   # Train MNIST classifier with misconfigurations
│   └── api_server.py      # Flask API with security vulnerabilities
├── osint_discovery/       # OSINT reconnaissance tools
│   └── scanner.py         # Directory scanner, config checker, fingerprinting
├── attacks/               # Attack modules
│   ├── data_poisoning.py  # Label flipping, backdoor injection
│   ├── model_extraction.py # Query-based model stealing
│   └── adversarial_evasion.py # FGSM adversarial examples
├── defenses/              # Defense framework
│   └── defense_framework.py # Access control, input validation, anomaly detection
├── metrics/               # Metrics and visualization
│   └── metrics_collector.py # Collect metrics, generate visualizations
├── data/                  # Data storage (simulated misconfigurations)
├── models/                # Model storage (simulated exposed models)
└── main.py               # Main orchestration script
```

## 🔧 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- At least 4GB RAM (for TensorFlow)
- ~500MB disk space

### Setup

1. **Clone or navigate to the project directory:**
   ```bash
   cd ml_osint_security
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Usage

### Quick Start: Full Demonstration

**Option 1: Without Model Extraction (Default)**

Run the complete demonstration (skips Step 4 - model extraction):

```bash
python main.py --full
```

**Expected runtime:** ~40-60 seconds

**Option 2: With Model Extraction (Requires API Server)**

For the complete attack chain including model extraction:

**Terminal 1: Start API Server**
```bash
python vulnerable_system/api_server.py
```

**Terminal 2: Run Full Demo**
```bash
python main.py --full --with-api-attacks
```

**Expected runtime:** ~90-120 seconds

This will:
1. ✅ Set up a vulnerable ML system (MNIST classifier)
2. 🔍 Perform OSINT discovery of exposed resources
3. ☠️ Execute data poisoning attack (25% poison rate)
4. 🎯 **Execute model extraction attack** (1000 API queries)
5. 🎭 Generate adversarial examples (FGSM)
6. 🛡️ Demonstrate defense framework
7. 📊 Collect metrics and generate visualizations

### Run Individual Steps

```bash
# Step 1: Setup vulnerable system
python main.py --step 1

# Step 2: OSINT discovery
python main.py --step 2

# Step 3: Data poisoning attack
python main.py --step 3

# Step 4: Model extraction (requires API server)
python main.py --step 4

# Step 5: Adversarial evasion
python main.py --step 5

# Step 6: Defense framework
python main.py --step 6

# Step 7: Metrics and visualization
python main.py --step 7
```

### Run Individual Modules

Each module can be run independently:

```bash
# Train vulnerable model
python vulnerable_system/model_trainer.py

# Start API server (in separate terminal)
python vulnerable_system/api_server.py

# Run OSINT discovery
python osint_discovery/scanner.py

# Execute data poisoning
python attacks/data_poisoning.py

# Model extraction attack
python attacks/model_extraction.py

# Adversarial evasion
python attacks/adversarial_evasion.py

# Defense framework demo
python defenses/defense_framework.py

# Collect metrics
python metrics/metrics_collector.py
```

## 📋 Components Overview

### 1. Vulnerable ML System

**Intentional Vulnerabilities:**
- ❌ Training data stored in world-readable directory
- ❌ Model weights saved without access control
- ❌ Configuration files expose metadata
- ❌ No integrity checks on model files
- ❌ API has no authentication
- ❌ No rate limiting
- ❌ Verbose error messages

**Files:**
- `vulnerable_system/model_trainer.py` - Creates misconfigured ML system
- `vulnerable_system/api_server.py` - Vulnerable Flask API

### 2. OSINT Discovery Module

**Capabilities:**
- 🔍 Directory scanning for exposed files
- 🔍 Storage misconfiguration detection
- 🔍 ML model fingerprinting (framework, architecture)
- 🔍 API vulnerability probing
- 📄 Comprehensive security report generation

**File:** `osint_discovery/scanner.py`

### 3. Attack Modules

#### a) Data Poisoning
- **Label Flipping:** Change labels to degrade accuracy
- **Feature Poisoning:** Add noise to training data
- **Backdoor Injection:** Insert trigger patterns for misclassification

**File:** `attacks/data_poisoning.py`

#### b) Model Extraction
- **Query-based extraction:** Build surrogate model via API queries
- **OSINT-enhanced:** Use discovered metadata for optimization
- **Agreement rate measurement:** Compare surrogate with original

**File:** `attacks/model_extraction.py`

#### c) Adversarial Evasion (FGSM)
- **Fast Gradient Sign Method:** Generate adversarial examples
- **Targeted attacks:** Force specific misclassifications
- **Transferability testing:** Test across models

**File:** `attacks/adversarial_evasion.py`

### 4. Defense Framework

**Security Controls:**
- 🛡️ **Access Control:** Authentication and authorization
- 🛡️ **Input Validation:** Detect anomalous/adversarial inputs
- 🛡️ **Rate Limiting:** Prevent rapid model extraction
- 🛡️ **Anomaly Detection:** Identify suspicious query patterns
- 🛡️ **Model Integrity:** Version control and hash verification

**File:** `defenses/defense_framework.py`

### 5. Metrics & Visualization

**Collected Metrics:**
- ⏱️ Time to discovery
- 📈 Attack success rates
- 📉 Model accuracy degradation
- 🛡️ Defense effectiveness
- 📊 OSINT advantage quantification

**Visualizations:**
- OSINT discovery results
- Attack success rates
- Model accuracy comparison
- Defense effectiveness
- OSINT intelligence advantage

**File:** `metrics/metrics_collector.py`

## 📊 Example Results

After running the full demonstration, you'll find:

```
metrics/results/
├── osint_discovery.png           # Exposed resources visualization
├── attack_success_rates.png       # Attack effectiveness
├── model_accuracy_comparison.png  # Clean vs poisoned vs surrogate
├── defense_effectiveness.png      # Defense layer analysis
├── osint_advantage.png            # OSINT impact visualization
├── summary_report.txt             # Comprehensive text report
└── all_metrics.json               # Complete metrics data
```

## 🔒 Security Best Practices Demonstrated

### ❌ Vulnerabilities Shown
1. Exposed training data and models
2. No access controls on ML resources
3. Information disclosure via API endpoints
4. No rate limiting enabling extraction
5. Lack of input validation
6. No integrity verification

### ✅ Defenses Implemented
1. **Access Control:** Role-based permissions
2. **Authentication:** Token-based auth system
3. **Input Validation:** Statistical anomaly detection
4. **Rate Limiting:** Query throttling
5. **Anomaly Detection:** Pattern recognition
6. **Model Versioning:** Integrity verification via hashing
7. **Monitoring:** Comprehensive logging and alerting

## 📖 Educational Use Cases

### For Students
- Understand ML security vulnerabilities
- Learn attack and defense techniques
- Practice security analysis
- Develop defensive mindset

### For Researchers
- Study OSINT-driven attack vectors
- Analyze defense effectiveness
- Develop new security measures
- Publish security findings

### For Practitioners
- Security audit ML systems
- Implement defensive measures
- Train security awareness
- Conduct penetration testing (authorized)

## 🎓 Learning Outcomes

After completing this demonstration, you will understand:

1. **OSINT Techniques:**
   - How to discover exposed ML resources
   - Configuration misconfiguration patterns
   - Model fingerprinting methods

2. **Attack Vectors:**
   - Data poisoning mechanisms
   - Model extraction via queries
   - Adversarial example generation

3. **Defense Strategies:**
   - Multi-layered security approach
   - Access control implementation
   - Anomaly detection systems

4. **Impact Assessment:**
   - Measuring attack success
   - Quantifying security improvements
   - Risk analysis

## ⚠️ Ethical Considerations

### Legal Compliance
- Only test systems you own or have written permission to test
- Respect terms of service and acceptable use policies
- Comply with computer fraud and abuse laws (CFAA, etc.)
- Obtain proper authorization before security testing

### Responsible Disclosure
- Report vulnerabilities to system owners
- Follow coordinated disclosure timelines
- Do not publish exploits without fixes available

### Academic Integrity
- Use for educational purposes only
- Cite sources appropriately
- Do not plagiarize or misrepresent work

## 🤝 Contributing

This is an educational project. If you find issues or have improvements:

1. Document the issue/enhancement
2. Ensure changes maintain educational value
3. Test thoroughly
4. Submit with clear explanation

## 📚 References

### Papers & Research
- Goodfellow et al. (2014) - "Explaining and Harnessing Adversarial Examples"
- Tramèr et al. (2016) - "Stealing Machine Learning Models via Prediction APIs"
- Biggio & Roli (2018) - "Wild Patterns: Ten Years After the Rise of Adversarial ML"
- Papernot et al. (2017) - "Practical Black-Box Attacks against Machine Learning"

### Frameworks & Tools
- TensorFlow/Keras - ML framework
- Flask - Web API framework
- CleverHans - Adversarial examples library (reference)
- Foolbox - Adversarial attacks library (reference)

### Standards & Guidelines
- OWASP ML Security Top 10
- NIST AI Risk Management Framework
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

## 📝 License

This project is provided for educational purposes. Use responsibly and ethically.

## 🆘 Troubleshooting

### Common Issues

**Issue:** TensorFlow installation fails
- **Solution:** Use Python 3.8-3.11, upgrade pip: `pip install --upgrade pip`

**Issue:** Out of memory during training
- **Solution:** Reduce batch size in model_trainer.py or use smaller dataset

**Issue:** API connection errors
- **Solution:** Ensure API server is running on port 5000: `python vulnerable_system/api_server.py`

**Issue:** Module import errors
- **Solution:** Run from project root, ensure virtual environment is activated

### Getting Help

For issues specific to this demonstration:
1. Check log file: `ml_osint_security.log`
2. Review error messages carefully
3. Ensure all dependencies are installed
4. Verify Python version compatibility

## 🏁 Conclusion

This demonstration shows how seemingly small misconfigurations can be discovered via OSINT and exploited to compromise ML systems. The key takeaways:

1. **Security is critical** for ML systems
2. **Defense-in-depth** is essential
3. **OSINT intelligence** significantly enhances attacks
4. **Proper configuration** prevents most vulnerabilities
5. **Continuous monitoring** detects attacks early

**Remember:** Use this knowledge to BUILD secure systems, not to BREAK them.

---

**⚠️ Final Warning:** This tool is for authorized security testing and education ONLY. Unauthorized use is illegal and unethical. Always obtain proper permission before testing any system you do not own.
