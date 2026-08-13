# OWASP Top 10: Cross-Site Scripting (XSS)

## Description
Cross-Site Scripting (XSS) occurs when an application includes untrusted data in a web page without proper validation or escaping/encoding. This allows attackers to execute malicious scripts in the victim's browser, steal sessions, deface websites, or redirect users to malicious sites.
- **Reflected XSS**: Input is reflected back in the HTTP response immediately.
- **Stored XSS**: Input is saved in a database/file and rendered later.
- **DOM-based XSS**: Malicious data is handled directly by client-side Javascript.

## Severity
- **High** / **Medium** (leads to session hijacking, cookie theft, or phishing).

## Common Patterns
- **Python (Flask/Django)**: Disabling auto-escaping using the `safe` filter or rendering raw HTML templates with user inputs directly.
  ```html
  <div>{{ user_input | safe }}</div>
  ```
- **Java (JSP/Servlets)**: Writing raw user input directly to the HTTP response output stream.
  ```java
  response.getWriter().println("<p>" + request.getParameter("comment") + "</p>");
  ```

## Prevention Strategies
1. **Context-Aware Output Encoding**: Encode HTML tags, attributes, CSS, and Javascript.
   - For HTML body: escape `<`, `>`, `&`, `"`, `'`.
   - In Python, use `html.escape()`.
   - In Java, use `StringEscapeUtils.escapeHtml4()` from Apache Commons Text.
2. **Content Security Policy (CSP)**: Establish a CSP HTTP header to restrict script execution source locations.
3. **HTTPOnly Cookies**: Use `HttpOnly` flag on cookies so they cannot be accessed by javascript (preventing session theft).
