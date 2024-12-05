import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Encryption {
    private static String ALG_SEMM_ENCRYPT;
    private static String ALG_ASEMM_ENCRYPT;
    private static String ALG_ASEMM_SIGNATURE;
    private static String ALG_AES_SECRET_KEY;

    private static String File_Input;
    private static String File_Output;
    private static String File_Info;

    private static String keystore_type;
    private static String keystore_path;
    private static String keystore_alias;
    private static String keystore_pass;
    private static String keystore_Trusted_alias;

    // files data
    private static byte[] Original_File_Bytes;
    private static byte[] Encrypted_File_Bytes;

    // keys
    private static PrivateKey private_Key;
    private static PublicKey public_TrustedA;
    private static SecretKey Secret_Symm_Key;

    // confi-info
    private static byte[] Digital_Signature;
    private static byte[] Encrypted_Symm_Key_Bytes;
    private static byte[] ivParameter;

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("need keystore path alias and password!");
        }
        keystore_path = args[0];
        keystore_alias = args[1];
        keystore_pass = args[2];

        setting_Alg();

        System.out.println("start: encryption");
        encryption();
    }

    public static void setting_Alg() {
        ALG_SEMM_ENCRYPT = "AES/CBC/PKCS5Padding";
        ALG_ASEMM_ENCRYPT = "RSA/ECB/PKCS1Padding";
        ALG_ASEMM_SIGNATURE = "SHA256withRSA";
        ALG_AES_SECRET_KEY = "AES";

        File_Input = "plaintext.txt";
    }

    public static void encryption() throws Exception {
        Original_File_Bytes = FileReader(File_Input);
        setting_keys();
        Digital_Signature = create_digital_signature();
        create_secret_key();
        Encrypted_File_Bytes = encrypt_data();
        Encrypted_Symm_Key_Bytes = encrypt_secret_key();
        // result
        // FileWriter(Encrypted_File_Bytes, "EncryptedFile.txt");
        FileWriter_Info(Encrypted_Symm_Key_Bytes, ivParameter, Digital_Signature);

    }

    private static void setting_keys() throws Exception {
        KeyStore storeA = KeyStore.getInstance(keystore_type);
        FileInputStream storeAStream = new FileInputStream(new File(keystore_path));
        storeA.load(storeAStream, keystore_pass.toCharArray());
        private_Key = (PrivateKey) storeA.getKey(keystore_alias, keystore_pass.toCharArray());
        public_TrustedA = storeA.getCertificate(keystore_Trusted_alias).getPublicKey();
    }

    // signing message to original data-file privateA and save the digitalSignature
    private static byte[] create_digital_signature() throws Exception {
        Signature digitalSign = Signature.getInstance(ALG_ASEMM_SIGNATURE);
        digitalSign.initSign(private_Key);
        digitalSign.update(Original_File_Bytes);
        // digitalSign.update("signature of: Sarit".getBytes());
        byte[] digitalSignature = digitalSign.sign();
        System.out.println("len: " + digitalSignature.length);
        System.out.println("digitalSignature : " + digitalSignature);
        return digitalSignature;
    }

    // create a Asymmetric-SecretKey
    private static void create_secret_key() throws Exception {
        KeyGenerator key = KeyGenerator.getInstance(ALG_AES_SECRET_KEY);
        key.init(256);
        SecretKey secret_key = key.generateKey();
        Secret_Symm_Key = secret_key;
    }

    // symmetric-encrypt_data of the fileInput with Secret_Symm_Key
    private static byte[] encrypt_data() throws Exception {
        byte[] iv = new byte[16];
        SecureRandom secret_random = new SecureRandom();
        secret_random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        FileOutputStream EncryptedOutput = new FileOutputStream(File_Output);
        Cipher cipher = Cipher.getInstance(ALG_SEMM_ENCRYPT);
        cipher.init(Cipher.ENCRYPT_MODE, Secret_Symm_Key, ivParameterSpec);
        CipherOutputStream cipherStream = new CipherOutputStream(EncryptedOutput, cipher);

        EncryptedOutput.write(cipher.update(Original_File_Bytes));
        EncryptedOutput.write(cipher.doFinal());
        EncryptedOutput.close();
        cipherStream.close();
        ivParameter = ivParameterSpec.getIV();
        byte[] encrypted_data = new byte[1024];
        encrypted_data = Files.readAllBytes(Paths.get(File_Output));
        Encrypted_File_Bytes = encrypted_data;
        return encrypted_data;
    }

    // Asymmetric-encrypt_Symm-Key of the encrypData-key by: publickey de-B
    private static byte[] encrypt_secret_key() throws Exception {
        byte[] keyBytes = Secret_Symm_Key.getEncoded();
        FileOutputStream fos = new FileOutputStream(File_Info);
        Cipher cipher = Cipher.getInstance(ALG_ASEMM_ENCRYPT);
        cipher.init(Cipher.PUBLIC_KEY, public_TrustedA);
        byte[] encrypted_key = cipher.doFinal(keyBytes);

        fos.write(Digital_Signature);
        fos.write(encrypted_key);
        fos.write(ivParameter);
        fos.close();
        return encrypted_key;
    }

    private static byte[] FileReader(String filepath) throws Exception {
        byte[] fileBytes = Files.readAllBytes(Paths.get(filepath));
        return fileBytes;
    }

    private static void FileWriter_Info(byte[] key, byte[] iv, byte[] sign) throws Exception {
        // File outputFile = new File(File_Info);
        FileOutputStream outputStream = new FileOutputStream(File_Info);
        outputStream.write(key);
        outputStream.write(iv);
        outputStream.write(sign);
        // outputStream.flush();
        outputStream.close();
    }
}

// public static void FilePrinter(byte[] fileBytes) throws Exception {
// for (byte b : fileBytes) {
// System.out.print((char) b);
// }
// }