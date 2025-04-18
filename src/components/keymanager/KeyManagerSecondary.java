package components.keymanager;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.sql.Date;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.crypto.SecretKey;

/**
 * Abstract class implementing the secondary methods of the KeyManager interface.
 * Uses newInstance() to prevent issues with iterating over keys and modifying the collection.
 */
public abstract class KeyManagerSecondary implements KeyManager {

    /**
     * Helper method to get all key names from the keystore without modifying the original instance.
     * 
     * @return A set of all key names in the keystore
     */
    private Set<String> getAllKeyNames() {
        // Create a temporary instance to avoid modifying this instance's state
        KeyManager temp = this.newInstance();
        temp.transferFrom(this);
        
        Set<String> keyNames = new HashSet<>();
        int size = temp.size();
        
        // Retrieve each key once from the temp instance
        for (int i = 0; i < size; i++) {
            Map<String, List<String>> metaData = new HashMap<>();
            temp.keyRetreival(metaData);
            
            // If we got a key, add its name to our set
            if (!metaData.isEmpty()) {
                String keyName = metaData.keySet().iterator().next();
                keyNames.add(keyName);
            }
        }
        
        return keyNames;
    }
    
    /**
     * Helper method to get the metadata for a specific key.
     * 
     * @param keyName Name of the key to retrieve metadata for
     * @return List of metadata for the key, or null if key doesn't exist
     */
    private List<String> getKeyMetadata(String keyName) {
        // Create a temporary instance to avoid modifying this instance's state
        KeyManager temp = this.newInstance();
        temp.transferFrom(this);
        
        int size = temp.size();
        for (int i = 0; i < size; i++) {
            Map<String, List<String>> metaData = new HashMap<>();
            temp.keyRetreival(metaData);
            
            if (!metaData.isEmpty() && metaData.containsKey(keyName)) {
                return new ArrayList<>(metaData.get(keyName));
            }
        }
        
        return null;
    }

    @Override
    public void keyRotation() {
        // Get all key names first
        Set<String> keyNames = getAllKeyNames();
        
        // Store existing key information
        Map<String, String> keyAccess = new HashMap<>();
        
        // For each key, record its access level
        for (String keyName : keyNames) {
            List<String> metadata = getKeyMetadata(keyName);
            if (metadata != null) {
                String keyAccessString = metadata.get(2);
                keyAccess.put(keyName, keyAccessString);
            }
        }
        
        // Now rotate each key (delete and recreate)
        for (Map.Entry<String, String> entry : keyAccess.entrySet()) {
            String keyName = entry.getKey();
            String access = entry.getValue();
            
            // Delete the old key
            this.keyDestruction(keyName);
            
            // Create a new key with the same name and access
            this.keyGenerator(keyName, access);
            this.keyStorage();
        }
    }

    @Override
    public void exportKeyLog(String fileName) {
        // Get all key names
        Set<String> keyNames = getAllKeyNames();
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName))) {
            for (String keyName : keyNames) {
                List<String> metadata = getKeyMetadata(keyName);
                
                if (metadata != null) {
                    writer.write("Key: " + keyName);
                    writer.newLine();
                    
                    // Write out metadata details
                    writer.write("\tID: " + metadata.get(0));
                    writer.newLine();
                    
                    // Convert timestamp to readable date if possible
                    String timestamp = metadata.get(1);
                    try {
                        long time = Long.parseLong(timestamp);
                        Date date = new Date(time);
                        writer.write("\tCreated: " + date.toString());
                    } catch (NumberFormatException e) {
                        writer.write("\tTimestamp: " + timestamp);
                    }
                    writer.newLine();
                    
                    writer.write("\tAccess Level: " + metadata.get(2));
                    writer.newLine();
                    
                    writer.write("\tSignature: " + metadata.get(3));
                    writer.newLine();
                    
                    writer.newLine(); // Extra line between keys
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void cleanupExpiredKeys() {
        // Get all key names first to avoid modification during iteration
        Set<String> keyNames = getAllKeyNames();
        
        for (String keyName : keyNames) {
            List<String> metadata = getKeyMetadata(keyName);
            
            if (metadata != null && metadata.size() > 1) {
                String creationDateStr = metadata.get(1);
                
                try {
                    long creationTimestamp = Long.parseLong(creationDateStr);
                    Date creationDate = new Date(creationTimestamp);
                    Instant creationInstant = creationDate.toInstant();
                    Instant oneMonthAgo = Instant.now().minus(30, ChronoUnit.DAYS);
                    
                    // Delete keys older than one month
                    if (creationInstant.isBefore(oneMonthAgo)) {
                        this.keyDestruction(keyName);
                    }
                } catch (NumberFormatException e) {
                    // Skip keys with invalid creation date format
                    System.err.println("Invalid creation date for key: " + keyName);
                }
            }
        }
    }

    @Override
    public List<String> findKeysByAccess(String access) {
        List<String> accessibleKeys = new ArrayList<>();
        Set<String> keyNames = getAllKeyNames();
        
        for (String keyName : keyNames) {
            List<String> metadata = getKeyMetadata(keyName);
            
            if (metadata != null && metadata.size() > 2) {
                String keyAccess = metadata.get(2);
                
                if (access.equals(keyAccess)) {
                    accessibleKeys.add(keyName);
                }
            }
        }
        
        return accessibleKeys;
    }

    @Override
    public boolean verifyKeySignatures(PublicKey publicKey) {
        Set<String> keyNames = getAllKeyNames();
        
        if (keyNames.isEmpty()) {
            // No keys to verify (according to specification, we should return false)
            return false;
        }
        
        boolean allValid = true;
        
        for (String keyName : keyNames) {
            List<String> metadata = getKeyMetadata(keyName);
            
            if (metadata != null && metadata.size() > 3) {
                String signatureString = metadata.get(3);
                
                try {
                    // Decode the Base64 signature
                    byte[] signatureBytes = Base64.getDecoder().decode(signatureString);
                    
                    // Verify the signature
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initVerify(publicKey);
                    signature.update(keyName.getBytes(StandardCharsets.UTF_8));
                    
                    if (!signature.verify(signatureBytes)) {
                        allValid = false;
                        break;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    allValid = false;
                    break;
                }
            } else {
                // Invalid metadata format
                allValid = false;
                break;
            }
        }
        
        return allValid;
    }

    @Override
    public int hashCode() {
        Set<String> keyNames = getAllKeyNames();
        return Objects.hash(keyNames);
    }

    @Override
    public String toString() {
        Set<String> keyNames = getAllKeyNames();
        return String.join(", ", keyNames);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        
        KeyManager other = (KeyManager) obj;
        
        // Compare key sets between this and other
        Set<String> thisKeyNames = this.getAllKeyNames();
        
        // Use temporary instance to get other's key names
        KeyManager tempOther = this.newInstance();
        tempOther.transferFrom(other);
        
        Set<String> otherKeyNames = new HashSet<>();
        int otherSize = tempOther.size();
        
        for (int i = 0; i < otherSize; i++) {
            Map<String, List<String>> metaData = new HashMap<>();
            tempOther.keyRetreival(metaData);
            
            if (!metaData.isEmpty()) {
                String keyName = metaData.keySet().iterator().next();
                otherKeyNames.add(keyName);
            }
        }
        
        // Compare key names and their metadata
        if (!thisKeyNames.equals(otherKeyNames)) {
            return false;
        }
        
        // Compare metadata for each key
        for (String keyName : thisKeyNames) {
            List<String> thisMetadata = this.getKeyMetadata(keyName);
            
            // Get metadata from other for this key
            List<String> otherMetadata = null;
            for (int i = 0; i < otherSize; i++) {
                Map<String, List<String>> metaData = new HashMap<>();
                tempOther.keyRetreival(metaData);
                
                if (!metaData.isEmpty() && metaData.containsKey(keyName)) {
                    otherMetadata = metaData.get(keyName);
                    break;
                }
            }
            
            // Compare metadata
            if (!Objects.equals(thisMetadata, otherMetadata)) {
                return false;
            }
        }
        

        return true;
    }
}