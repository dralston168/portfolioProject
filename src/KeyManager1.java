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

    private byte[] truePassword;

    /**
     * Creator of initial representation.
     */
    private void createNewRep() {

        // TODO - fill in body
        
        if(password==null||truePassword==null) {
            try {
                this.keystore = KeyStore.getInstance("JKS");
                this.keystore.load(null, null); 
                this.metaData = new HashMap<>();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        if(truePassword.equals(password)){
            try (FileInputStream fis = new FileInputStream(this.file)) {
                this.keystore = KeyStore.getInstance("JKS");
                // Attempt to load with the given password
                StringBuilder sb = new StringBuilder();
                for (byte b : this.password) {
                sb.append((char) b); // cast byte to char
}               char[] charArray = new char[sb.length()];

                for (int i = 0; i < sb.length(); i++) {
                charArray[i] = sb.charAt(i);
            }
                keystore.load(fis, charArray);
                this.metaData = new HashMap<>();
                System.out.println("Keystore successfully loaded.");
            } catch (Exception e) {
                System.err.println("Failed to load keystore: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    /*
     * Constructors -----------------------------------------------------------
     */

    /**
     * constructor for exsisting keystore
     */
    public KeyManager1(byte[] password,String file, byte[] access, byte[] truePassword) {

        // TODO - fill in body
        this.password = password;
        this.file = file;
        this.truePassword = truePassword;
        this.createNewRep();

    }

    /**
     * construtor for new keystore
     */

    public KeyManager1(){
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
                + "Violation of: source is of dynamic type NaturalNumberExample";
        /*
         * This cast cannot fail since the assert above would have stopped
         * execution in that case.
         */
        KeyManager1 localSource = (KeyManager1) source;
        
         // Clear this keystore first
         this.clear();
    
        // Copy password and file references
        this.password = localSource.password;
        this.file = localSource.file;
    
        // Copy all keys and metadata from source to this
        int sourceSize = localSource.size();
        for (int i = 0; i < sourceSize; i++) {
        Map<String, List<String>> metaData = new HashMap<>();
        localSource.keyRetreival(metaData);
        
        // Get the first key name from metadata (as done in keyRetreival)
        String keyName = metaData.keySet().iterator().next();
        List<String> keyMetadata = metaData.get(keyName);
        
        // Generate a key with the same name and access level
        String keyID = keyMetadata.get(0);
        String access = keyMetadata.get(2);
        this.keyGenerator(keyID, access);
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
            char[] password = System.getenv("KEYSTORE_PASSWORD").toCharArray();
            
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
        try {
        // Clear and populate the provided map with metadata
        metaData.clear();
        metaData.putAll(this.metaData);
        
        // If there's at least one key in the metadata
        if (!metaData.isEmpty()) {
            // Get the first key name from the metadata
            String keyName = metaData.keySet().iterator().next();
            
            // Create a password for key retrieval (should match the one used in keyStorage)
            char[] password =  System.getenv("KEYSTORE_PASSWORD").toCharArray();
            
            // Create a protection parameter for the key
            KeyStore.PasswordProtection protParam = 
                new KeyStore.PasswordProtection(password);
            
            // Retrieve the secret key entry from the keystore
            KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry) 
                this.keystore.getEntry(keyName, protParam);
            
            // Set this.key to the retrieved secret key
            if (skEntry != null) {
                this.key = skEntry.getSecretKey();
            }
        }
    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
        e.printStackTrace();
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
