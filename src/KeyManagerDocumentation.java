import java.security.KeyPair;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import components.keymanager.KeyManager1;

public class KeyManagerDocumentation {

    public static void main(String[] args) {
        System.out.println("KeyManager Documentation Demo");
        System.out.println("===========================");
        
        byte[] password = "SecurePassword123".getBytes();
        KeyManager1 keyManager = new KeyManager1(password);
        
        generateSampleKeys(keyManager);
        
        System.out.println("\nTotal keys in keystore: " + keyManager.size());
        
        displaySampleKey(keyManager);
        
        // Export the key log as documentation
        System.out.println("\nExporting key documentation to 'keystore_documentation.txt'...");
        keyManager.exportKeyLog("keystore_documentation.txt");
        System.out.println("Documentation exported successfully!");
        
        // Display instructions for viewing the documentation
        System.out.println("\nYou can view the detailed key documentation in the file:");
        System.out.println("keystore_documentation.txt");
        System.out.println("\nThe documentation contains detailed information about each key:");
        System.out.println("- Key IDs");
        System.out.println("- Creation timestamps");
        System.out.println("- Access levels");
        System.out.println("- Digital signatures");
    }
    
    /**
     * Generates several sample keys with different access levels
     * @param keyManager The KeyManager instance
     */
    private static void generateSampleKeys(KeyManager1 keyManager) {
        System.out.println("\nGenerating sample keys...");
        
        KeyPair adminKey = keyManager.keyGenerator("admin_key", "admin");
        keyManager.keyStorage();
        System.out.println("Created admin key");
        
        KeyPair userKey1 = keyManager.keyGenerator("user_key_1", "user");
        keyManager.keyStorage();
        System.out.println("Created user key 1");
        
        KeyPair userKey2 = keyManager.keyGenerator("user_key_2", "user");
        keyManager.keyStorage();
        System.out.println("Created user key 2");
        
        KeyPair guestKey = keyManager.keyGenerator("guest_key", "guest");
        keyManager.keyStorage();
        System.out.println("Created guest key");
        
        KeyPair apiKey = keyManager.keyGenerator("api_key", "service");
        keyManager.keyStorage();
        System.out.println("Created API key");
    }
    
    /**
     * Retrieves and displays information about a sample key
     * @param keyManager The KeyManager instance
     */
    private static void displaySampleKey(KeyManager1 keyManager) {
        Map<String, List<String>> metaData = new HashMap<>();
        keyManager.keyRetreival(metaData);
        
        if (!metaData.isEmpty()) {
            String keyName = metaData.keySet().iterator().next();
            List<String> metadata = metaData.get(keyName);
            
            System.out.println("\nSample key information:");
            System.out.println("- Key ID: " + metadata.get(0));
            System.out.println("- Created: " + metadata.get(1));
            System.out.println("- Access Level: " + metadata.get(2));
            System.out.println("- Signature: " + metadata.get(3).substring(0, 20) + "...");
        }
    }
}