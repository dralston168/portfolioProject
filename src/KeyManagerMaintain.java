import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import components.keymanager.KeyManager1;

/**
 * Simple proof of concept showing keystore maintenance using KeyManager1
 */
public class KeyManagerMaintain {

    public static void main(String[] args) {
        // Create password and initialize KeyManager1
        byte[] password = "password123".getBytes();
        KeyManager1 keyManager = new KeyManager1(password);
        
        // Store public keys manually
        Map<String, PublicKey> publicKeys = new HashMap<>();
        
        System.out.println("1. Generating keys with different access levels...");
        
        // Generate admin key
        KeyPair adminKeyPair = keyManager.keyGenerator("admin_key", "admin");
        publicKeys.put("admin_key", adminKeyPair.getPublic());
        keyManager.keyStorage();
        
        // Generate regular key
        KeyPair regularKeyPair = keyManager.keyGenerator("regular_key", "standard");
        publicKeys.put("regular_key", regularKeyPair.getPublic());
        keyManager.keyStorage();
        
        // Generate guest key
        KeyPair guestKeyPair = keyManager.keyGenerator("guest_key", "guest");
        publicKeys.put("guest_key", guestKeyPair.getPublic());
        keyManager.keyStorage();
        
        System.out.println("Keys generated successfully. Total keys: " + keyManager.size());
        
        // Export key log
        System.out.println("\n2. Exporting key log...");
        keyManager.exportKeyLog("keys.log");
        System.out.println("Key log exported to keys.log");
        
        // Find keys by access level
        System.out.println("\n3. Finding keys by access level...");
        List<String> adminKeys = keyManager.findKeysByAccess("admin");
        System.out.println("Admin keys: " + adminKeys);
        
        // Verify key signatures
        System.out.println("\n4. Verifying key signatures...");
        for (String keyName : publicKeys.keySet()) {
            PublicKey publicKey = publicKeys.get(keyName);
            boolean isValid = keyManager.verifyKeySignatures(publicKey);
            System.out.println("Key " + keyName + " signature valid: " + isValid);
        }
        
        // Clean up expired keys
        System.out.println("\n5. Cleaning up expired keys...");
        keyManager.cleanupExpiredKeys();
        System.out.println("Expired keys cleaned up. Remaining keys: " + keyManager.size());
        
        // Rotate keys
        System.out.println("\n6. Rotating keys...");
        keyManager.keyRotation();
        System.out.println("Keys rotated successfully. Total keys: " + keyManager.size());
        
        // Export updated key log
        System.out.println("\n7. Exporting updated key log...");
        keyManager.exportKeyLog("keys_updated.log");
        System.out.println("Updated key log exported to keys_updated.log");
    }
}