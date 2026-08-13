# OWASP Top 10: Broken Access Control

## Description
Broken Access Control occurs when users can act outside of their intended permissions. This can lead to unauthorized information disclosure, modification, or destruction of data, or performing a business function outside their limits. Common issues include IDOR (Insecure Direct Object References), path traversal, and missing access validation on endpoints.

## Severity
- **High** (leads to data leaks, privilege escalation, or resource abuse).

## Common Patterns
- **Insecure Direct Object Reference (IDOR)**: Exposing database primary keys directly in URLs and loading resources without verifying if the requesting user owns them:
  ```python
  # Python Flask vulnerable route
  @app.route('/invoice/<invoice_id>')
  def view_invoice(invoice_id):
      # Missing check: is invoice_id owned by current_user?
      return db.get_invoice(invoice_id)
  ```
- **Path Traversal**: Accepting filename parameters from the user and appending them to the file system path without validation, allowing access to files like `/etc/passwd` or system configurations:
  ```java
  // Java vulnerable path traversal
  String filename = request.getParameter("file");
  File file = new File("/var/www/uploads/" + filename);
  ```

## Prevention Strategies
1. **Deny by Default**: Always assume access is denied unless explicitly allowed.
2. **Access Control Policies**: Define access control at the server-side, verifying that the current user owns or is authorized to view/edit the specific resource.
   ```python
   @app.route('/invoice/<invoice_id>')
   def view_invoice(invoice_id):
       invoice = db.get_invoice(invoice_id)
       if invoice.user_id != current_user.id:
           abort(403) # Forbidden
       return invoice
   ```
3. **Safe File Operations**: Sanitize path parameters, resolve absolute paths, and verify they lie within the allowed storage directory, or use file ID lookups.
   - In Java:
     ```java
     File file = new File("/var/www/uploads/", filename);
     if (!file.getCanonicalPath().startsWith("/var/www/uploads/")) {
         throw new SecurityException("Unauthorized file path access");
     }
     ```
