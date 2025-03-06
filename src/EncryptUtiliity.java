public interface EncryptUtiliity extends EncryptUtiliityKernel {
    // Secondary Methods

    /**
    * Encrypts the given plaintext using a combination of substitution and
    * shift ciphers.
    *
    * @param plaintext
    *            The text to encrypt.
    * @return The encrypted ciphertext.
    * @requires plaintext != null
    * @ensures |result| == |plaintext.length| &&
    *          the result is the output of applying substitution and shift ciphers &&
    *          plaintext != result; 
    */
StringBuilder encrypt(StringBuilder plaintext);

    /**
    * Decrypts the given ciphertext using a combination of substitution and
    * shift ciphers.
    *
    * @param ciphertext
    *            The text to decrypt.
    * @return The decrypted plaintext.
    * @requires ciphertext != null; 
    * @ensures |result| == |ciphertext.length| &&
    *          the result is the output of reversing the applied substitution and shift ciphers &&
    *          result != ciphertext
    */
    StringBuilder decrypt(StringBuilder ciphertext);



}
    