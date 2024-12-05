
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.DECRYPT_MODE;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryption {
    // algs
    private static String ALG_SEMM_ENCRYPT;
    private static String ALG_ASEMM_ENCRYPT;
    private static String ALG_ASEMM_SIGNATURE;
    private static String ALG_AES_SECRET_KEY;

    private static String File_Input;
    private static String File_Input_info;
    private static String File_Output;

    private static String keystore_type;
    private static String keystore_path;
    private static String keystore_alias;
    private static String keystore_pass;
    private static String keystore_Trusted_alias;

    private static byte[] Digital_Signature_Bytes;
    private static byte[] secretKeyEncrypted_Bytes;
    private static byte[] ivParameter_Bytes;

    private static PrivateKey private_Key;
    private static PublicKey public_TrustedB;
    private static IvParameterSpec ivParameterSpec;
    private static SecretKey secretKey_decrypted;
    private static byte[] Decrypted_SymmKey_Bytes;
    private static byte[] Decrypted_File_Bytes;

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("need keystore path alias and password!");
        }
        keystore_path = args[0];
        keystore_alias = args[1];
        keystore_pass = args[2];

        setting_Alg();

        System.out.println("start: decryption");
        decryption();

    }

    public static void setting_Alg() {
        ALG_SEMM_ENCRYPT = "AES/CBC/PKCS5Padding";
        ALG_ASEMM_ENCRYPT = "RSA/ECB/PKCS1Padding";
        ALG_ASEMM_SIGNATURE = "SHA256withRSA";
        ALG_AES_SECRET_KEY = "AES";

        File_Input = "EncryptedFile.txt";
        File_Input_info = "EncryptionInfo.txt";
    }

    public static void decryption() throws Exception {
        // Encryption_File_Bytes = FileReader(File_Input);
        setting_keys();
        FileReader_Info();
        decrypt_secret_key();
        decrypt_dataEncrypted();

        if (!valid_digital_signature()) {
            System.out.println("digital signature is not valid");
        }
    }

    public static void setting_keys() throws Exception {
        KeyStore storeB = KeyStore.getInstance(keystore_type);
        FileInputStream storeBStream = new FileInputStream(new File(keystore_path));
        storeB.load(storeBStream, keystore_pass.toCharArray());
        private_Key = (PrivateKey) storeB.getKey(keystore_alias, keystore_pass.toCharArray());
        Certificate trusted_cert = storeB.getCertificate(keystore_Trusted_alias);
        public_TrustedB = trusted_cert.getPublicKey();
    }

    private static void decrypt_secret_key() throws Exception {
        Cipher cipher = Cipher.getInstance(ALG_ASEMM_ENCRYPT);
        cipher.init(Cipher.DECRYPT_MODE, private_Key);
        Decrypted_SymmKey_Bytes = cipher.doFinal(secretKeyEncrypted_Bytes);
        secretKey_decrypted = new SecretKeySpec(Decrypted_SymmKey_Bytes, ALG_AES_SECRET_KEY);
    }

    private static byte[] decrypt_dataEncrypted() throws Exception {
        FileInputStream fis = new FileInputStream(File_Input);
        FileOutputStream fos = new FileOutputStream(File_Output);
        Cipher cipher = Cipher.getInstance(ALG_SEMM_ENCRYPT);
        cipher.init(DECRYPT_MODE, secretKey_decrypted, ivParameterSpec);
        byte[] buffer = new byte[1024];
        int read;
        while ((read = fis.read(buffer)) != -1) {
            fos.write(cipher.update(buffer, 0, read));
        }

        Decrypted_File_Bytes = buffer;

        fos.write(cipher.doFinal());
        if (valid_digital_signature() == false) {
            System.out.println("valid_digital_signature err");
        }
        fis.close();
        fos.close();
        return buffer;
    }

    private static boolean valid_digital_signature() throws Exception {
        Signature signature = Signature.getInstance(ALG_ASEMM_SIGNATURE);
        signature.initVerify(public_TrustedB);
        signature.update(Decrypted_File_Bytes);
        boolean valid = signature.verify(Digital_Signature_Bytes); // true or false
        return valid;
    }

    private static void FileReader_Info() throws Exception {
        FileInputStream fis = new FileInputStream(File_Input_info);
        byte[] encryptedSecretKey = new byte[256];
        fis.read(encryptedSecretKey);
        byte[] iv = new byte[16];
        fis.read(iv);
        byte[] sign = new byte[256];
        fis.read(sign);
        fis.close();
        secretKeyEncrypted_Bytes = encryptedSecretKey;
        ivParameter_Bytes = iv;
        ivParameterSpec = new IvParameterSpec(iv);
        Digital_Signature_Bytes = sign;
    }
}
