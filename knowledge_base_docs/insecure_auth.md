# OWASP Top 10: Insecure Authentication (Identification and Authentication Failures)

## Description
Insecure Authentication occurs when authentication sessions or user credentials are not protected correctly. Common issues include weak password hashing algorithms (e.g., MD5, SHA1), credentials sent in cleartext, session identifiers exposed in URLs, lack of rate limiting on login endpoints, or session tokens that do not expire.

## Severity
- **High** (direct compromise of user accounts and privilege escalation).

## Common Patterns
- Hashing passwords with obsolete, fast algorithms like MD5 or plain SHA-256 (which are vulnerable to GPU rainbow table cracking):
  ```python
  # Python vulnerable code
  import hashlib
  pass_hash = hashlib.md5(password.encode()).hexdigest()
  ```
- Storing passwords in plain text.
- Reusing global secret keys for token generation / signature validation.

## Prevention Strategies
1. **Strong Adaptive Hashing Algorithms**: Always use slow, salt-based hashing algorithms such as **bcrypt**, **Argon2**, or **scrypt**.
   - **Python (bcrypt)**:
     ```python
     import bcrypt
     # Hash password
     hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
     # Verify password
     assert bcrypt.checkpw(password.encode(), hashed)
     ```
   - **Java (BCrypt)**:
     ```java
     import org.mindrot.jbcrypt.BCrypt;
     // Hash password
     String hashed = BCrypt.hashpw(password, BCrypt.gensalt());
     // Verify password
     boolean matches = BCrypt.checkpw(password, hashed);
     ```
2. **Session Security**: Always use cryptographically secure session IDs, regenerate them upon authentication, enforce token expiration times, and secure them with `Secure` and `HttpOnly` cookie flags.
3. **Multi-Factor Authentication (MFA)**: Implement MFA for all users, especially administrators.
