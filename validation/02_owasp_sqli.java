import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class UserDatabaseManager {

    // Vulnerability: Hardcoded secret (line 9)
    private static final String DB_PASSWORD = "SuperSecretPassword123!";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/users";
    private static final String DB_USER = "admin";

    // Code Smell: Long method and Poor Naming (single letter 'u', 'p', 'res')
    public void doAuthAndFetchDataAndProcessUserInformation(String u, String p) {
        Connection c = null;
        Statement s = null;
        ResultSet res = null;

        try {
            c = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            s = c.createStatement();
            
            // Vulnerability: SQL Injection via concatenation (line 24)
            String query = "SELECT * FROM users WHERE username = '" + u + "' AND password = '" + p + "'";
            res = s.executeQuery(query);
            
            while (res.next()) {
                String email = res.getString("email");
                String role = res.getString("role");
                
                if (role != null) {
                    if (role.equals("admin")) {
                        System.out.println("User is admin: " + email);
                    } else if (role.equals("manager")) {
                        System.out.println("User is manager: " + email);
                    } else if (role.equals("user")) {
                        System.out.println("User is regular user: " + email);
                    } else {
                        System.out.println("User has unknown role: " + role);
                    }
                } else {
                    System.out.println("User role is null for email: " + email);
                }
                
                String address = res.getString("address");
                if (address != null && !address.isEmpty()) {
                    System.out.println("User address is: " + address);
                    if (address.contains("NY")) {
                        System.out.println("User is from New York.");
                    } else if (address.contains("CA")) {
                        System.out.println("User is from California.");
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try { if (res != null) res.close(); } catch (Exception e) {}
            try { if (s != null) s.close(); } catch (Exception e) {}
            try { if (c != null) c.close(); } catch (Exception e) {}
        }
    }
}
