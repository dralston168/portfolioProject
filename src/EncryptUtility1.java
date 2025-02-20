interface EncryptionUtility {

    // Kernel Methods

    /**
     * Applies a simple substitution cipher to the input text.
     *
     * @param text
     *            The input text.
     * @return The substituted text.
     */
    String substitute(String text);

    /**
     * Reverses the substitution cipher.
     *
     * @param text
     *            The substituted text.
     * @return The original text.
     */
    String reverseSubstitute(String text);

    /**
     * Shifts each character in the text by a specified number of positions.
     *
     * @param text
     *            The input text.
     * @return The shifted text.
     */
    String shiftCharacters(String text);

     /**
     * Reverses the character shift operation by shifting letters backward.
     * Non-letter characters remain unchanged.
     *
     * @param text The input string to reverse shift.
     * @return The reversed (original) string with characters moved backward.
     */
    String reverseShiftCharacters(String text);

    // Secondary Methods

    /**
     * Encrypts the given plaintext using a combination of substitution and
     * shift ciphers.
     *
     * @param plaintext
     *            The text to encrypt.
     * @return The encrypted ciphertext.
     */
    StringBuilder encrypt(String plaintext);

    /**
     * Decrypts the given ciphertext using a combination of substitution and
     * shift ciphers.
     *
     * @param ciphertext
     *            The text to decrypt.
     * @return The decrypted plaintext.
     */
    StringBuilder decrypt(StringBuilder ciphertext);
}

public class EncrpytUtility1 implements EncryptionUtility {

    /*
     * Represents the generated encryption key
     */
    private StringBuilder key;

    /*
     * Represents the text to be encrypted
     */
    private StringBuilder plaintext;

    /*
     * Represents the encrypted text to be decrypted
     */
    private StringBuilder cipherText;

    /*
     * The number of positions to shift
     */
    private int shift;

    /**
     * Constructor to initialize the plaintext with a default shift value.
     *
     * @param input
     *            The plaintext to encrypt.
     */
    public EncrpytUtility1(String input) {
        this.plaintext = new StringBuilder(input);
        this.shift = 10;
    }

    /**
     * Constructor to initialize the plaintext with a custom shift value.
     *
     * @param input
     *            The plaintext to encrypt.
     * @param shifts
     *            The number of positions to shift.
     */
    public EncrpytUtility1(String input, int shifts) {
        this.plaintext = new StringBuilder(input);
        this.shift = shifts;
    }

    @Override
    public String substitute(String text) {
        StringBuilder substituted = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                char substitutedChar = (char) (c + 1);
                if (substitutedChar > 'z' && Character.isLowerCase(c)) {
                    substitutedChar = 'a';
                } else if (substitutedChar > 'Z' && Character.isUpperCase(c)) {
                    substitutedChar = 'A';
                }
                substituted.append(substitutedChar);
            } else {
                substituted.append(c);
            }
        }
        return substituted.toString();
    }

    @Override
    public String reverseSubstitute(String text) {
        StringBuilder original = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                char originalChar = (char) (c - 1);
                if (originalChar < 'a' && Character.isLowerCase(c)) {
                    originalChar = 'z';
                } else if (originalChar < 'A' && Character.isUpperCase(c)) {
                    originalChar = 'Z';
                }
                original.append(originalChar);
            } else {
                original.append(c);
            }
        }
        return original.toString();
    }

    @Override
    public String shiftCharacters(String text) {
        StringBuilder shifted = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                char shiftedChar = (char) (base
                        + (c - base + this.shift + 26) % 26);
                shifted.append(shiftedChar);
            } else {
                shifted.append(c);
            }
        }
        return shifted.toString();
    }

    @Override
    public String reverseShiftCharacters(String text) {
    StringBuilder reversed = new StringBuilder();
    for (char c : text.toCharArray()) {
        if (Character.isLetter(c)) {
            char base = Character.isLowerCase(c) ? 'a' : 'A';
            char reversedChar = (char) (base
                    + (c - base - this.shift + 26) % 26);
            reversed.append(reversedChar);
        } else {
            reversed.append(c);
        }
    }
    return reversed.toString();
}

    @Override
    public StringBuilder encrypt(String plaintext) {
        String substituted = this.substitute(plaintext);
        String ciphertext = this.shiftCharacters(substituted);

        this.cipherText = new StringBuilder(ciphertext);
        return this.cipherText;
    }

    @Override
    public StringBuilder decrypt(StringBuilder ciphertext) {
        String unshifted = this.reverseShiftCharacters(ciphertext.toString());

        String plaintext = this.reverseSubstitute(unshifted);

        return new StringBuilder(plaintext);
    }

    public static void main(String[] args) {

        EncrpytUtility1 encryptor = new EncrpytUtility1("Hello, World!", 5);

        StringBuilder ciphertext = encryptor
                .encrypt(encryptor.plaintext.toString());
        System.out.println("Encrypted: " + ciphertext);

        StringBuilder decryptedText = encryptor.decrypt(ciphertext);
        System.out.println("Decrypted: " + decryptedText);
    }
}
