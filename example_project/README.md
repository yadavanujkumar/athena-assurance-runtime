# Example Project — ATHENA Demonstration

This is a minimal Python project that demonstrates ATHENA's autonomous assurance capabilities.

## What It Contains

- `src/app.py` — A simple application with an **intentional** `eval()` vulnerability for demonstration purposes
- `tests/test_app.py` — Safe tests that validate the application's safe functions

## Running the ATHENA Demo

```bash
# From the repository root
cd example_project

# Initialize ATHENA for this project
athena init .

# Run a full inspection — ATHENA will detect the eval() vulnerability
athena inspect .

# Run a full autonomous cycle (detect, reason, plan remediation)
athena run . --yes

# Check findings
athena findings .

# Check decisions
athena decisions .

# Check status
athena status .

# Export assurance bundle
athena export .
```

## Expected ATHENA Output

ATHENA should detect:
1. **"Dynamic eval usage"** finding in `src/app.py`
2. Create evidence linking the finding to the specific line
3. Map the finding to NIST AI RMF:MANAGE and NIST AI RMF:MEASURE
4. Propose remediation: replace `eval()` with `ast.literal_eval()`
5. Request human approval for the MODIFY action
6. Record the decision request in durable memory

## Security Note

The `eval()` in `src/app.py` is intentional and clearly marked as a demonstration.
**Never use `eval()` with user-controlled input in production code.**
