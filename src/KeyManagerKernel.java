import java.security.KeyPair;
import java.util.List;
import java.util.Map;

public interface KeyManagerKernel {

    // Kernel Methods

    /**
     * Generates a key and stores it into this.key with metadata
     *
     * @param keyID
     *            an ID assoicated with a key to keep track of the specific role of the key
     * @updates this.key
     * @returns the KeyPair associated with the digital signature of the key
     * @ensures this.key is a randomly generated 256-bit AES encryption key
     *
     */
    KeyPair keyGenerator(String keyID);

    /**
     * Transfers this.key into KEYSTORE
     *
     * @param keyName
     *            The name that this.key will be stored under in KEYSTORE
     *
     * @clears this.key
     *
     * @requires KeyName is not already in KEYSTORE
     *
     * @ensures this.key is stored into KEYSTORE under the name of KeyName
     */
    void keyStorage(String keyName);

    /**
     * Retrieves a random key from the keystore
     *
     *
     * @param metaData
     *            A Map that will hold the metadata such as the key usage,
     *            access key, and expiration data, of the retrieved key after
     *            the method is called
     *
     * @replaces metaData with a Map of this.metaData with the particular key name
     *           that matches KeyName
     *
     * @requires keyName is a key in KEYSTORE
     *
     *
     * @ensures The key {KeyName} is retrieved from KEYSTORE (not removed) and metaData is a map
     *          with the keyName as the key and the metadata is a List<String> as the value associated
     *          with the key
     *          
     */
    void keyRetreival(Map<String, List<String>> metaData);

    /**
     * Destroys a keyName and removes it from the [KEYSTORE]
     *
     * @param keyName
     *            The name of the key in the Keystore
     *
     * @requires keyName is a key in KEYSTORE
     * @ensures keyName is removed from KEYSTORE
     */
    void keyDestruction(String keyName);

    /**
     * Returns the number of keys in the KEYSTORE.
     *
     * @return The number of keys in the KEYSTORE
     *
     * @ensures Returns the amount of keys in the KeyStore
     */
    int size();

}
