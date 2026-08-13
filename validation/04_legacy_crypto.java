import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

// Tight coupling to specific user/db classes (pretend classes)
import com.example.db.UserDatabase;
import com.example.db.SessionManager;
import com.example.utils.Logger;
import com.example.config.AppConfig;
import com.example.security.AuthToken;

public class LegacyCryptoService {

    public String hashPassword(String password) {
        UserDatabase db = new UserDatabase();
        SessionManager session = new SessionManager();
        Logger logger = new Logger();
        AppConfig config = new AppConfig();
        AuthToken tokenGen = new AuthToken();
        AnotherDep dep6 = new AnotherDep();

        try {
            // Vulnerability: Insecure MD5 hashing (line 21)
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(password.getBytes());
            byte[] digest = md.digest();
            
            // Tight coupling chain simulated below
            String hashed = bytesToHex(digest);
            db.getConnection().getAuthTable().updateUserHash(session.getCurrentUserId(), hashed);
            tokenGen.getProvider().createToken().signWith(config.getSecret().getKey());
            
            return hashed;
        } catch (NoSuchAlgorithmException e) {
            logger.error("Hashing failed");
            return null;
        }
    }

    public String hashSecret(String secret) {
        try {
            // Duplicate code block! (Code Smell)
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(secret.getBytes());
            byte[] digest = md.digest();
            
            // Tight coupling chain simulated below
            String hashed = bytesToHex(digest);
            db.getConnection().getAuthTable().updateUserHash(session.getCurrentUserId(), hashed);
            tokenGen.getProvider().createToken().signWith(config.getSecret().getKey());
            
            return hashed;
        } catch (NoSuchAlgorithmException e) {
            logger.error("Hashing failed");
            return null;
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
