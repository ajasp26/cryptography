import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * This class demonstrates AES-128 encryption using CBC mode and PKCS5 padding.
 */
public class AESEncryption {

    /**
     * The main method to test AES-128 encryption.
     *
     * @param args the command-line arguments (none required).
     */
    public static void main(String[] args) {
        try {
            // Example key; in a real application, keys should be managed and stored
            // securely
            String key = "0123456789abcdef";

            // Generating a random initialization vector (IV)
            String initVector = generateInitVector();

            // Encrypting a sample string "Hello World"
            String encrypted = encrypt(key, initVector, "Hello World");
            System.out.println("Encrypted: " + encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates a random initialization vector (IV) for AES encryption.
     *
     * @return a base64 encoded string representation of the IV.
     */
    public static String generateInitVector() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    /**
     * Encrypts the given plaintext value using AES-128 with the provided key and
     * IV.
     *
     * @param key        the secret key for AES-128 encryption.
     * @param initVector the initialization vector (IV) for the AES encryption.
     * @param value      the plaintext value to be encrypted.
     * @return a base64 encoded string of the encrypted value.
     */
    public static String encrypt(String key, String initVector, String value) {
        try {
            // Decoding the base64 encoded IV and converting the key into bytes
            IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(initVector));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            // Initializing the cipher for encryption
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            // Performing the encryption
            byte[] encrypted = cipher.doFinal(value.getBytes());

            // Returning the encrypted value as a base64 encoded string
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}