# OWASP Top 10: SQL Injection (Injection)

## Description
SQL Injection (SQLi) occurs when untrusted user input is directly concatenated or interpolated into a database query string instead of using parameterized queries (also known as prepared statements). This allows attackers to manipulate the query structure, bypass authentication, read, modify, or delete database contents, or execute administrative operations.

## Severity
- **Critical** / **High** (depending on the sensitivity of the data and database privileges).

## Common Patterns
- **Python**: Using formatted strings, `+` operators, or `%` interpolation to construct SQL strings for cursor execution:
  ```python
  cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
  ```
- **Java**: Concatenating strings in JDBC statements:
  ```java
  String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
  Statement stmt = connection.createStatement();
  ResultSet rs = stmt.executeQuery(query);
  ```

## Prevention Strategies
1. **Parameterized Queries / Prepared Statements**: Always bind parameters to placeholders (`?`, `%s`, `:param`) instead of embedding input.
   - **Python (sqlite3)**:
     ```python
     cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))
     ```
   - **Java (JDBC Prepared Statements)**:
     ```java
     String query = "SELECT * FROM users WHERE username = ?";
     PreparedStatement pstmt = connection.prepareStatement(query);
     pstmt.setString(1, userInput);
     ResultSet rs = pstmt.executeQuery();
     ```
2. **Object-Relational Mapping (ORM)**: Use secure ORMs like Hibernate (Java) or SQLAlchemy/Django ORM (Python) which use prepared statements under the hood.
