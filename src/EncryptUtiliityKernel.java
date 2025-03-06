public interface EncryptUtiliityKernel {
    
    // Kernel Methods
    /**
     * Applies a simple substitution cipher to the input text.
     *
     * @param text
     *            The input text.
     * @return The substituted text.
     * @requires text != null; 
     * @ensures |result| == |text.length| && 
     *          the result is a susbstituion based on the key &&
     *          text != result
     */
    StringBuilder substitute(StringBuilder text);

   /**
    * Reverses the substitution cipher.
    *
    * @param text
    *           The substituted text.
    * @return The original text.
    * @requires text != null; // text must not be null
    * @ensures |result| == |text.length| && 
    *          the result is the orginal text using the key
    */
    StringBuilder reverseSubstitute(StringBuilder text);

    /**
    * Shifts each character in the text by a specified number of positions.
    *
    * @param text
    *            The input text.
    * @return The shifted text.
    * @requires text != null; // text must not be null
    * @ensures |result| == |text.length| && 
     *          the result is a shift based on the key &&
     *          text != result
     */
    StringBuilder shiftCharacters(StringBuilder text);

    /**
    * Reverses the character shift operation by shifting letters backward.
    * Non-letter characters remain unchanged.
    *
    * @param text The input string to reverse shift.
    * @return The reversed (original) string with characters moved backward.
    * @requires text != null; 
    * @ensures |result| == |text.length| && 
    *          the result is the original text before shifting using the key
    */
    StringBuilder reverseShiftCharacters(StringBuilder text);

    /**
    * Generates a cryptographic key for use in substitution or shifting operations.
    * The key can be of any length and may include letters, numbers, or symbols.
    *
    * @return A randomly generated key of the specified length.
    * @ensures result != null && |result| > 0; 
    */
    StringBuilder generateKey();

    

    
} 
