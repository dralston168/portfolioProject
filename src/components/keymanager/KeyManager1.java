package components.keymanager;


import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.util.Map;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * @Convention
 * 1. The KeyStore instance 'keystore' is always initialized - either empty or loaded from a file.
 * 2. If 'password' is non-null, it contains the characters of the password used for the keystore.
 * 3. If 'file' is non-null, it contains the path to the keystore file.
 * 4. The 'metaData' map associates key IDs with metadata lists, where each list contains:
 *    - Index 0: Key ID (String)
 *    - Index 1: Timestamp of creation (String representation of milliseconds)
 *    - Index 2: Access information (String)
 *    - Index 3: Digital signature (Base64-encoded String)
 * 5. 'keyID' holds the identifier of the most recently generated key.
 * 6. All operations involving the keystore handle exceptions internally.
 * 7. If the password or the truePassword is not set by the client then a new KeyStore will be generated
 * 
 * @Correspondence
 * 1. This class represents a key management system that generates, stores, retrieves, 
 *    and destroys cryptographic keys.
 * 2. Each entry in the keystore corresponds to a secret key with its associated metadata.
 * 3. The number of keys managed by this KeyManager corresponds to the number of entries 
 *    in the keystore.
 * 4. The security of the key management system corresponds to the strength of the 
 *    cryptographic algorithms used (AES-256 for symmetric keys, RSA-2048 for asymmetric keys)
 *    and the protection of the keystore password.
 * 5. The 'metaData' map provides a layer of abstraction over the keystore, allowing for
 *    additional information to be associated with each key without modifying the keystore format.
 */
 
public class KeyManager1 extends KeyManagerSecondary  {
    /*
     * Private members --------------------------------------------------------
     */

    /**
     * Representation of {@code this}.
     */
    private KeyStore keystore;

    private SecretKey key;

    private Map<String, List<String>> metaData;

    private String keyID;

    private byte[] password;

    private String file;

    

    /**
     * Creator of initial representation.
     */
    private void createNewRep() {

        // TODO - fill in body
        try {
            // Initialize a new empty keystore instance
            this.keystore = KeyStore.getInstance("JKS");
            
            // Load with null parameters to initialize an empty keystore
            this.keystore.load(null, null);
            
            // Initialize metadata storage
            this.metaData = new HashMap<>();
            
            System.out.println("New keystore created successfully.");
        } catch (KeyStoreException e) {
            System.err.println("Failed to get keystore instance: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Failed to create new keystore: " + e.getMessage());
            e.printStackTrace();
        }
    }
    

    /*
     * Constructors -----------------------------------------------------------
     */

    /**
     * constructor for new keystore
     */
    public KeyManager1(byte[] password) {

        // TODO - fill in body
        this.password = password;
        this.createNewRep();

    }


    /*
     * Standard methods -------------------------------------------------------
     */

     @Override
    public final KeyManager newInstance() {
        try {
            return this.getClass().getConstructor().newInstance();
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(
                    "Cannot construct object of type " + this.getClass());
        }
    }

    @Override
    public final void clear(){
        this.metaData.clear();
        Enumeration<String> aliases;
        try {
            aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                keystore.deleteEntry(alias);
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        
    };
    

    @Override
    public final void transferFrom(KeyManager source){
        assert source != null : "Violation of: source is not null";
        assert source != this : "Violation of: source is not this";
        assert source instanceof KeyManager1 : ""
            + "Violation of: source is of dynamic type KeyManager1";
        
        // This cast cannot fail since the assert above would have stopped
        // execution in that case.
        KeyManager1 localSource = (KeyManager1) source;
        
        // Clear this keystore first
        this.clear();
        
        // Copy password and file references
        this.password = localSource.password;
        this.file = localSource.file;
        
        // Create a snapshot of source's metadata to avoid modification during iteration
        Map<String, List<String>> sourceMetaData = new HashMap<>(localSource.metaData);
        
        // For each key in source, generate a new key in this with the same metadata
        for (Map.Entry<String, List<String>> entry : sourceMetaData.entrySet()) {
            String keyName = entry.getKey();
            List<String> keyMetadata = entry.getValue();
            
            // Extract access level (index 2)
            String access = keyMetadata.get(2);
            
            // Generate and store a new key with the same name and access level
            this.keyGenerator(keyName, access);
            this.keyStorage();
        }
        
        // Clear the source
        localSource.clear();
    }
    

    /*
     * Kernel methods ---------------------------------------------------------
     */

    @Override
    public final KeyPair keyGenerator(String keyID, String access){
        try {
        // Generate a 256-bit AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        this.key = keyGen.generateKey();
        
        // Create a KeyPair for digital signature (using RSA)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        
        // Create signature for the key ID
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(keyID.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        
        // Encode signature as Base64 string
        String signatureString = Base64.getEncoder().encodeToString(signatureBytes);
        
        // Store metadata about the key
        List<String> metadata = new ArrayList<>();
        metadata.add(keyID);                         // Index 0: Key ID
        metadata.add(System.currentTimeMillis() + ""); // Index 1: Timestamp
        metadata.add(access);                   // Index 2: Access information
        metadata.add(signatureString);               // Index 3: Digital signature
        
        // Associate metadata with the key ID
        this.metaData.put(keyID, metadata);
        this.keyID = keyID;
        
        return keyPair;
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
        e.printStackTrace();
        return null;
    }
    }

    @Override
    public void keyStorage() {
        try {
            // Create a password for the key entry
            byte[] byteArray = this.password; // corresponds to "Hello"
            String str = new String(byteArray, StandardCharsets.UTF_8);
            char[] password= str.toCharArray();
            
            // Create a KeyStore.ProtectionParameter for the key
            KeyStore.PasswordProtection protParam = 
                new KeyStore.PasswordProtection(password);
            
            // Create a KeyStore.SecretKeyEntry with the key
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(this.key);
            
            // Set the entry in the KeyStore
            this.keystore.setEntry(this.keyID, skEntry, protParam);
            
            // Clear the key
            this.key = null;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    } 

    @Override
    public void keyRetreival(Map<String, List<String>> metaData) {
        if (metaData == null) {
            throw new IllegalArgumentException("Metadata map cannot be null");
        }
        
        try {
            // If no keys in the keystore, return an empty map
            if (this.metaData.isEmpty()) {
                metaData.clear();
                return;
            }
            
            // Pick one key from metadata (for demonstration purposes, taking the first one)
            String keyName = this.metaData.keySet().iterator().next();
            List<String> metadata = this.metaData.get(keyName);
            
            // Clear and add just this one key to the provided map
            metaData.clear();
            metaData.put(keyName, new ArrayList<>(metadata));
            
            // Retrieve the actual key from the keystore
            if (this.password != null) {
                // Convert byte[] password to char[]
                String passStr = new String(this.password, StandardCharsets.UTF_8);
                char[] passwordChars = passStr.toCharArray();
                
                // Create a protection parameter for the key
                KeyStore.PasswordProtection protParam =
                    new KeyStore.PasswordProtection(passwordChars);
                
                // Retrieve the secret key entry from the keystore
                KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry)
                    this.keystore.getEntry(keyName, protParam);
                
                // Set this.key to the retrieved secret key
                if (skEntry != null) {
                    this.key = skEntry.getSecretKey();
                }
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | 
                UnrecoverableEntryException e) {
            e.printStackTrace();
            metaData.clear(); // Clear the map on error
        }
    }

    @Override
    public void keyDestruction(String keyName) {
        try {
            // Remove the key from the keystore
            this.keystore.deleteEntry(keyName);
            
            // Remove metadata associated with the key
            this.metaData.remove(keyName);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }
    
    @Override
    public int size() {
        try {
            return this.keystore.size();
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return 0;
        }
    }
}
