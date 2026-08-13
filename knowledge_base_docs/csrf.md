# OWASP Top 10: Cross-Site Request Forgery (CSRF)

## Description
Cross-Site Request Forgery (CSRF) is an attack that forces an end-user to execute unwanted actions on a web application in which they are currently authenticated. If the victim is a normal user, a successful CSRF attack can force state-changing requests like transferring funds or changing email addresses. If the victim is an administrator, the attack can compromise the entire web application.

## Severity
- **Medium** (since it requires an active session and victim interaction, but has high impact on state changes).

## Common Patterns
- Web applications accepting state-changing GET requests.
- Endpoints processing POST/PUT/DELETE forms or AJAX requests without validating a unique anti-CSRF token.
- Relying solely on default session cookies for authorization.

## Prevention Strategies
1. **Synchronizer Token Pattern**: Generate a cryptographically strong, unique, and random token for each user session. Embed it in forms and verify it matches the session state before processing any POST/PUT/DELETE request.
2. **SameSite Cookie Attribute**: Set `SameSite=Strict` or `SameSite=Lax` on all cookies to ensure they are not sent with cross-site requests.
3. **Double Submit Cookie**: Use a cookie and a custom header containing the same random value, verifying they match on the server.
