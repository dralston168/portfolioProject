import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.After;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KeyManagerTest {
    
    private KeyManager keyManager;
    private byte[] password;
    private KeyPair testKeyPair;
    private String testKeyName = "test-key";
    private String testAccessLevel = "admin";
    
    /**
     * Set up a fresh KeyManager instance before each test
     */
    @Before
    public void setUp() {
        // Initialize test password
        password = "TestPassword123".getBytes(StandardCharsets.UTF_8);
        
        // Create a new KeyManager
        keyManager = new KeyManager1(password);
        
        // Generate test key
        testKeyPair = keyManager.keyGenerator(testKeyName, testAccessLevel);
        keyManager.keyStorage();
    }
    
    /**
     * Clean up after each test
     */
    @After
    public void tearDown() {
        // Delete any created log files
        deleteFileIfExists("keystore_test_log.txt");
        deleteFileIfExists("keystore_rotation_test.txt");
    }
    
    /**
     * Helper method to delete a file if it exists
     */
    private void deleteFileIfExists(String filePath) {
        File file = new File(filePath);
        if (file.exists()) {
            file.delete();
        }
    }
    
    /**
     * Test case for key generation and storage
     */
    @Test
    public void testKeyGenerationAndStorage() {
        // Check if key was generated and stored correctly
        assertEquals(1, keyManager.size());
        
        // Generate another key
        String newKeyName = "another-test-key";
        keyManager.keyGenerator(newKeyName, "user");
        keyManager.keyStorage();
        
        // Check if size increased
        assertEquals(2, keyManager.size());
        
        // Check if the key can be found by its access level
        List<String> userKeys = keyManager.findKeysByAccess("user");
        assertTrue(userKeys.contains(newKeyName));
    }
    
    /**
     * Test case for key retrieval
     */
    @Test
    public void testKeyRetrieval() {
        // Prepare a map to store key metadata
        Map<String, List<String>> metaData = new HashMap<>();
        
        // Retrieve a key
        keyManager.keyRetreival(metaData);
        
        // Check if key metadata was retrieved
        assertFalse(metaData.isEmpty());
        assertTrue(metaData.containsKey(testKeyName));
        
        // Check if metadata contains the correct access level
        List<String> keyMetadata = metaData.get(testKeyName);
        assertNotNull(keyMetadata);
        assertTrue(keyMetadata.size() >= 3);
        assertEquals(testAccessLevel, keyMetadata.get(2));
    }
    
    /**
     * Test case for key destruction
     */
    @Test
    public void testKeyDestruction() {
        // Initial size should be 1
        assertEquals(1, keyManager.size());
        
        // Destroy the key
        keyManager.keyDestruction(testKeyName);
        
        // Size should now be 0
        assertEquals(0, keyManager.size());
        
        // Check that the key is no longer found by its access level
        List<String> adminKeys = keyManager.findKeysByAccess(testAccessLevel);
        assertFalse(adminKeys.contains(testKeyName));
    }
    
    /**
     * Test case for key rotation
     */
    @Test
    public void testKeyRotation() {
        // Get the initial size
        int initialSize = keyManager.size();
        
        // Store the initial access level
        List<String> initialAdminKeys = keyManager.findKeysByAccess(testAccessLevel);
        assertTrue(initialAdminKeys.contains(testKeyName));
        
        // Rotate keys
        keyManager.keyRotation();
        
        // Size should remain the same
        assertEquals(initialSize, keyManager.size());
        
        // Key should still be found by its access level
        List<String> adminKeysAfterRotation = keyManager.findKeysByAccess(testAccessLevel);
        assertTrue(adminKeysAfterRotation.contains(testKeyName));
        
        // Verify that the key was actually rotated by checking if signature verification fails
        // Note: This assumes that the new keys have different signatures
        assertFalse(keyManager.verifyKeySignatures(testKeyPair.getPublic()));
    }
    
    /**
     * Test case for finding keys by access level
     */
    @Test
    public void testFindKeysByAccess() {
        // Add keys with different access levels
        keyManager.keyGenerator("admin-key-1", "admin");
        keyManager.keyStorage();
        keyManager.keyGenerator("user-key-1", "user");
        keyManager.keyStorage();
        keyManager.keyGenerator("admin-key-2", "admin");
        keyManager.keyStorage();
        keyManager.keyGenerator("service-key", "service");
        keyManager.keyStorage();
        
        // Find keys by access level
        List<String> adminKeys = keyManager.findKeysByAccess("admin");
        List<String> userKeys = keyManager.findKeysByAccess("user");
        List<String> serviceKeys = keyManager.findKeysByAccess("service");
        List<String> guestKeys = keyManager.findKeysByAccess("guest");
        
        // Verify admin keys
        assertEquals(3, adminKeys.size());
        assertTrue(adminKeys.contains(testKeyName));
        assertTrue(adminKeys.contains("admin-key-1"));
        assertTrue(adminKeys.contains("admin-key-2"));
        
        // Verify user keys
        assertEquals(1, userKeys.size());
        assertTrue(userKeys.contains("user-key-1"));
        
        // Verify service keys
        assertEquals(1, serviceKeys.size());
        assertTrue(serviceKeys.contains("service-key"));
        
        // Verify guest keys (shouldn't be any)
        assertEquals(0, guestKeys.size());
    }
    
    /**
     * Test case for verifying key signatures
     */
    @Test
    public void testVerifyKeySignatures() {
        // When only one key exists, and we verify with the same public key used to generate it
        assertTrue(keyManager.verifyKeySignatures(testKeyPair.getPublic()));
        
        // Generate a new key with its own key pair
        KeyPair anotherKeyPair = keyManager.keyGenerator("another-key", "user");
        keyManager.keyStorage();
        
        // The original public key should now fail verification because it can't verify all keys
        assertFalse(keyManager.verifyKeySignatures(testKeyPair.getPublic()));
        
        // But the new public key should also fail because it can only verify its own key
        assertFalse(keyManager.verifyKeySignatures(anotherKeyPair.getPublic()));
    }
    
    /**
     * Test case for exporting key log
     */
    @Test
    public void testExportKeyLog() {
        String logFilePath = "keystore_test_log.txt";
        
        // Export the key log
        keyManager.exportKeyLog(logFilePath);
        
        // Verify the log file was created
        File logFile = new File(logFilePath);
        assertTrue(logFile.exists());
        
        // Check log file content contains key information
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String content = reader.lines().reduce("", (acc, line) -> acc + line + "\n");
            assertTrue(content.contains(testKeyName));
            assertTrue(content.contains(testAccessLevel));
        } catch (Exception e) {
            fail("Failed to read log file: " + e.getMessage());
        }
    }
    
    /**
     * Test case for cleaning up expired keys
     * Note: This is a basic test since we can't easily simulate key expiration
     */
    @Test
    public void testCleanupExpiredKeys() {
        // Initial size should be 1
        assertEquals(1, keyManager.size());
        
        // Run cleanup (shouldn't affect newly created keys)
        keyManager.cleanupExpiredKeys();
        
        // Size should still be 1
        assertEquals(1, keyManager.size());
    }
    
    /**
     * Test case for the transferFrom method
     */
    @Test
    public void testTransferFrom() {
        // Create a second key manager
        KeyManager otherManager = new KeyManager1(password);
        
        // Add a key to the other manager
        otherManager.keyGenerator("other-key", "guest");
        otherManager.keyStorage();
        
        // Check initial sizes
        assertEquals(1, keyManager.size());
        assertEquals(1, otherManager.size());
        
        // Transfer from the other manager to this one
        keyManager.transferFrom(otherManager);
        
        // Source should be empty now
        assertEquals(0, otherManager.size());
        
        // Target should have the transferred key
        assertEquals(1, keyManager.size());
        
        // The key should now be found by the "guest" access level
        List<String> guestKeys = keyManager.findKeysByAccess("guest");
        assertEquals(1, guestKeys.size());
    }
    
    /**
     * Test case for the clear method
     */
    @Test
    public void testClear() {
        // Initial size should be 1
        assertEquals(1, keyManager.size());
        
        // Clear the key manager
        keyManager.clear();
        
        // Size should now be 0
        assertEquals(0, keyManager.size());
    }
    
    /**
     * Integration test case for multiple operations
     */
    @Test
    public void testIntegratedOperations() {
        // Generate multiple keys
        keyManager.keyGenerator("key1", "user");
        keyManager.keyStorage();
        keyManager.keyGenerator("key2", "admin");
        keyManager.keyStorage();
        
        // Check size after adding keys
        assertEquals(3, keyManager.size());
        
        // Verify key access levels
        List<String> adminKeys = keyManager.findKeysByAccess("admin");
        assertEquals(2, adminKeys.size());
        assertTrue(adminKeys.contains(testKeyName));
        assertTrue(adminKeys.contains("key2"));
        
        // Export to log file
        String logFilePath = "keystore_rotation_test.txt";
        keyManager.exportKeyLog(logFilePath);
        
        // Rotate keys
        keyManager.keyRotation();
        
        // Size should remain the same after rotation
        assertEquals(3, keyManager.size());
        
        // Destroy one key
        keyManager.keyDestruction("key1");
        
        // Size should decrease by 1
        assertEquals(2, keyManager.size());
        
        // Run cleanup
        keyManager.cleanupExpiredKeys();
        
        // Export after operations
        keyManager.exportKeyLog(logFilePath);
    }
}
