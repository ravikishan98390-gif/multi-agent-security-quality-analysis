# OWASP Top 10: Hardcoded Secrets (Cryptographic Failures)

## Description
Hardcoding credentials, passwords, private keys, API keys, or database connection strings directly in source code is an extremely common vulnerability. Once code is pushed to version control, these secrets can be leaked to unauthorized parties, leading to complete service compromise.

## Severity
- **Critical** (leads to instant authentication bypass / resource access).

## Common Patterns
- **Python**:
  ```python
  API_KEY = "sk-live-5a4f7832bc99ef01a"
  DB_PASS = "admin123"
  ```
- **Java**:
  ```java
  private static final String AWS_SECRET_KEY = "AQIDAHgdb1r...";
  ```

## Prevention Strategies
1. **Environment Variables**: Load secrets from the environment at runtime using `os.getenv` (Python) or `System.getenv` (Java).
   - **Python**:
     ```python
     import os
     from dotenv import load_dotenv
     load_dotenv()
     api_key = os.getenv("API_KEY")
     ```
   - **Java**:
     ```java
     String dbPassword = System.getenv("DB_PASSWORD");
     ```
2. **Secrets Managers**: Utilize cloud-native secret vaults like AWS Secrets Manager, HashiCorp Vault, Google Secret Manager, or Azure Key Vault.
3. **Scan Tools**: Set up git pre-commit hooks (like `git-secrets` or `trufflehog`) to scan code and prevent secrets from ever being committed.
