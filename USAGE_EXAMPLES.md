# Usage Examples and Tutorials

This document provides detailed examples and tutorials for using the OSINT-driven adversarial attacks demonstration.

## Table of Contents
1. [Quick Start](#quick-start)
2. [Step-by-Step Tutorial](#step-by-step-tutorial)
3. [Advanced Usage](#advanced-usage)
4. [Custom Scenarios](#custom-scenarios)

---

## Quick Start

### Run Everything at Once

The simplest way to see the full demonstration:

```bash
# Activate virtual environment
source venv/bin/activate  # or: venv\Scripts\activate on Windows

# Run full demonstration
python main.py --full --skip-confirmation
```

**Output:** Complete demonstration in ~5-10 minutes with all metrics and visualizations.

---

## Step-by-Step Tutorial

### Tutorial 1: Setting Up and Attacking a Vulnerable ML System

#### Step 1: Create the Vulnerable System

```bash
python main.py --step 1
```

**What happens:**
- Downloads MNIST dataset (60K training images)
- Trains a CNN classifier (~98% accuracy)
- Saves model to `models/exposed/` ( no access control)
- Saves training data to `data/misconfigured/` ( world-readable)
- Creates config files with metadata ( exposes architecture)

**Files created:**
```
models/exposed/
 model_v1.0.keras
 weights_v1.0.h5
 model_config_v1.0.json

data/misconfigured/
 x_train.npy
 y_train.npy
 x_test.npy
 y_test.npy
 metadata.json
```

#### Step 2: OSINT Discovery

```bash
python main.py --step 2
```

**What happens:**
- Scans directories for exposed files
- Identifies misconfigurations
- Fingerprints ML model framework
- Generates security report

**Example output:**
```
EXPOSED DATA FOUND: ./data/misconfigured/x_train.npy
EXPOSED MODEL FOUND: ./models/exposed/model_v1.0.keras
EXPOSED CONFIG FOUND: ./models/exposed/model_config_v1.0.json
CRITICAL: Security control access_control is disabled in model_config_v1.0.json

Risk Level: HIGH (Score: 65)
```

**Report location:** `osint_discovery_report.json`

#### Step 3: Data Poisoning Attack

```bash
python main.py --step 3
```

**What happens:**
- Loads exposed training data (discovered via OSINT)
- Injects label flips into 10% of training samples
- Retrains model with poisoned data
- Measures accuracy degradation

**Example results:**
```
Clean model accuracy: 0.9812
Poisoned model accuracy: 0.8543
Accuracy drop: 0.1269 (12.9%)
```

**Key insight:** Even 10% poisoning significantly degrades performance!

#### Step 4: Adversarial Evasion Attack

```bash
python main.py --step 5  # Skip extraction for now
```

**What happens:**
- Uses OSINT-discovered model path
- Generates adversarial examples with FGSM (Î=0.15)
- Tests evasion success rate
- Measures perturbation magnitude

**Example results:**
```
Clean accuracy: 0.9800
Adversarial accuracy: 0.2100
Misclassification rate: 0.7800 (78%)
Average perturbation: 0.000847
```

**Key insight:** Tiny perturbations (imperceptible to humans) fool the model!

#### Step 5: Defense Framework

```bash
python main.py --step 6
```

**What happens:**
- Implements access control (RBAC)
- Deploys input validation
- Enables rate limiting
- Adds model integrity checks

**Example output:**
```
Admin accessing /info:  Allowed
User accessing /info:  Denied
Valid input:  Accepted
Invalid shape:  Rejected - Invalid shape: expected (28, 28, 1), got (32, 32, 1)
Query 51+ (rate limit):  Blocked - Rate limit exceeded: 50 queries per 60s
```

**Key insight:** Multi-layered defenses catch attacks at different stages!

#### Step 6: Metrics and Visualization

```bash
python main.py --step 7
```

**What happens:**
- Collects metrics from all previous steps
- Generates visualizations (PNG files)
- Creates comprehensive summary report

**Output files:**
```
metrics/results/
 osint_discovery.png
 attack_success_rates.png
 model_accuracy_comparison.png
 defense_effectiveness.png
 osint_advantage.png
 summary_report.txt
 all_metrics.json
```

---

## Advanced Usage

### Tutorial 2: Model Extraction Attack (Requires API Server)

#### Terminal 1: Start API Server

```bash
# Activate virtual environment
source venv/bin/activate

# Start vulnerable API
python vulnerable_system/api_server.py
```

**Output:**
```
VULNERABLE ML API SERVER
  WARNING: This is an intentionally vulnerable API
Starting server on 127.0.0.1:5000
```

**Keep this running!**

#### Terminal 2: Run Model Extraction

```bash
# Activate virtual environment in new terminal
source venv/bin/activate

# Run extraction attack
python attacks/model_extraction.py
```

**What happens:**
1. Exploits `/info` endpoint to get model metadata (OSINT)
2. Generates 1000 query samples
3. Queries API to get predictions
4. Trains surrogate model on query results
5. Tests surrogate accuracy

**Example results:**
```
Gathering OSINT metadata...
  Found metadata: 10 classes, input shape [28, 28, 1]

Querying target model...
  Completed 1000 queries in 32.45s (30.8 queries/sec)

Training surrogate model...
  Training accuracy: 0.9456
  Validation accuracy: 0.9389

Evaluating extraction success...
  Surrogate accuracy: 0.9245
  Original accuracy: 0.9812
  Model agreement: 0.9567
  Accuracy gap: 0.0567
```

**Key insight:** With OSINT metadata, surrogate model achieves 92.45% accuracy with just 1000 queries!

### Tutorial 3: Backdoor Attack

```python
# Custom script: backdoor_demo.py

from attacks.data_poisoning import DataPoisoner
import numpy as np

# Initialize poisoner
poisoner = DataPoisoner(data_dir='./data/misconfigured')
poisoner.load_exposed_data()

# Inject backdoor (trigger: 3x3 white square in corner)
x_poisoned, y_poisoned = poisoner.backdoor_attack(
    percentage=5,           # Poison 5% of data
    trigger_size=3,         # 3x3 pixel trigger
    target_label=0          # Force classification to "0"
)

# Retrain model
poisoned_model, _, metrics = poisoner.retrain_with_poisoned_data(
    x_poisoned, y_poisoned,
    model_save_path='./models/exposed/model_backdoor.keras',
    epochs=5
)

# Test backdoor
x_triggered, y_original = poisoner.apply_trigger_to_test_data(
    trigger_size=3,
    num_samples=100
)

# Predict on triggered samples
predictions = poisoned_model.predict(x_triggered)
predicted_labels = np.argmax(predictions, axis=1)

# Calculate success rate
backdoor_success = np.mean(predicted_labels == 0)
print(f"Backdoor success rate: {backdoor_success:.2%}")
# Expected: >90% success rate
```

### Tutorial 4: Targeted Adversarial Attack

```python
# Custom script: targeted_attack.py

from attacks.adversarial_evasion import AdversarialEvader
import numpy as np

# Load model and data
evader = AdversarialEvader(model_path='./models/exposed/model_v1.0.keras')
x_test = np.load('./data/misconfigured/x_test.npy')
y_test = np.load('./data/misconfigured/y_test.npy')

# Select images of digit "7"
indices = np.where(y_test == 7)[0][:10]
x_sevens = x_test[indices]

# Target: make all "7"s be classified as "1"
y_target = np.ones(len(x_sevens), dtype=int)

# Generate targeted adversarial examples
x_adv = evader.targeted_fgsm_attack(
    x_sevens,
    y_target,
    epsilon=0.05,
    iterations=20
)

# Evaluate
metrics = evader.evaluate_attack_success(
    x_sevens,
    x_adv,
    y_test[indices],
    y_target=y_target
)

print(f"Targeted attack success: {metrics['targeted_success_rate']:.2%}")
# Expected: ~70-90% success
```

---

## Custom Scenarios

### Scenario 1: Test Your Own Model

```python
# custom_model_test.py

from defenses.defense_framework import DefenseFramework
import numpy as np

# Load your model
from tensorflow import keras
your_model = keras.models.load_model('path/to/your/model.keras')

# Set up defense framework
config = {
    'input_shape': [28, 28, 1],  # Adjust to your model
    'value_range': (0, 1),
    'rate_limit_window': 60,
    'max_queries_per_window': 100
}

framework = DefenseFramework(config=config)

# Test input validation
test_input = np.random.uniform(0, 1, (1, 28, 28, 1))
is_valid, reason = framework.input_validator.validate_input(test_input)

if is_valid:
    prediction = your_model.predict(test_input)
    print(f"Prediction: {prediction}")
else:
    print(f"Input rejected: {reason}")
```

### Scenario 2: Custom Defense Configuration

```python
# custom_defense.py

from defenses.defense_framework import DefenseFramework

# Strict defense configuration
strict_config = {
    'input_shape': [28, 28, 1],
    'value_range': (0, 1),
    'rate_limit_window': 60,
    'max_queries_per_window': 10,  # Very strict
}

framework = DefenseFramework(config=strict_config)

# Create different user roles
admin_token = framework.access_control.create_user(
    'admin',
    'admin',
    ['predict', 'info', 'statistics', 'admin_panel']
)

analyst_token = framework.access_control.create_user(
    'security_analyst',
    'analyst',
    ['info', 'statistics', 'audit_logs']
)

basic_user_token = framework.access_control.create_user(
    'user',
    'user',
    ['predict']
)

# Test access control
resources = ['predict', 'info', 'statistics', 'admin_panel']
for token, name in [(admin_token, 'Admin'),
                     (analyst_token, 'Analyst'),
                     (basic_user_token, 'User')]:
    print(f"\n{name} access:")
    for resource in resources:
        allowed, _ = framework.access_control.verify_access(token, resource)
        status = "" if allowed else ""
        print(f"  {resource}: {status}")
```

### Scenario 3: Measure OSINT Advantage

```python
# measure_osint_advantage.py

from attacks.adversarial_evasion import AdversarialEvader
import numpy as np

# Load data
x_test = np.load('./data/misconfigured/x_test.npy')
y_test = np.load('./data/misconfigured/y_test.npy')

# Scenario 1: WITH OSINT (white-box)
print("Scenario 1: WITH OSINT (direct model access)")
evader_osint = AdversarialEvader(model_path='./models/exposed/model_v1.0.keras')

samples = x_test[:100]
labels = y_test[:100]

x_adv_osint = evader_osint.fgsm_attack(samples, labels, epsilon=0.15)
metrics_osint = evader_osint.evaluate_attack_success(samples, x_adv_osint, labels)

print(f"  Misclassification rate: {metrics_osint['misclassification_rate']:.2%}")

# Scenario 2: WITHOUT OSINT (black-box via surrogate)
print("\nScenario 2: WITHOUT OSINT (using surrogate model)")
evader_no_osint = AdversarialEvader(model_path='./models/exposed/surrogate_model.keras')

x_adv_no_osint = evader_no_osint.fgsm_attack(samples, labels, epsilon=0.15)

# Test on original model
from tensorflow import keras
original_model = keras.models.load_model('./models/exposed/model_v1.0.keras')
preds = np.argmax(original_model.predict(x_adv_no_osint), axis=1)
misclass_rate = 1 - np.mean(preds == labels)

print(f"  Misclassification rate: {misclass_rate:.2%}")

# Calculate advantage
advantage = metrics_osint['misclassification_rate'] - misclass_rate
print(f"\nOSINT Advantage: {advantage:.2%} higher success rate")
```

---

## Performance Tuning

### Speed Up Training

```python
# Quick training for demos
python main.py --step 1  # Use default 3-5 epochs

# For better accuracy (slower)
# Edit vulnerable_system/model_trainer.py:
# Change epochs=5 to epochs=10
```

### Reduce Memory Usage

```python
# In model_trainer.py, reduce batch size:
# Change batch_size=128 to batch_size=64

# Or use smaller subset of data:
# x_train = x_train[:10000]
# y_train = y_train[:10000]
```

### Faster Model Extraction

```python
# In model_extraction.py:
# Reduce queries:
query_samples = extractor.generate_query_samples(num_samples=500)  # Instead of 1000

# Reduce training epochs:
surrogate, metrics = extractor.train_surrogate_model(
    query_samples, predictions, epochs=5  # Instead of 10
)
```

---

## Troubleshooting Examples

### Problem: API connection refused

```bash
# Check if API is running
curl http://127.0.0.1:5000/health

# If not, start it:
python vulnerable_system/api_server.py
```

### Problem: Out of memory

```python
# Reduce batch size in training scripts
# Or limit dataset size:
x_train = x_train[:30000]  # Use only 30K samples
```

### Problem: Module not found

```bash
# Ensure you're in project root
cd ml_osint_security

# Verify virtual environment
which python  # Should show venv path

# Reinstall if needed
pip install -r requirements.txt
```

---

## Next Steps

After completing these tutorials:

1. **Experiment:** Try different attack parameters
2. **Customize:** Adapt to your own models/datasets
3. **Research:** Read referenced papers for deeper understanding
4. **Apply:** Use insights to secure real ML systems
5. **Share:** Teach others about ML security

**Remember:** Always obtain proper authorization before testing any system!
