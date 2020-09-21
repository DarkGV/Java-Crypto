package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.util.Arrays;

/**
 * Implementation of the AES cipher as a ByteArrayMixer
 */
public class RSACipher implements ByteArrayMixer {

    private String keyFile;
    private String mode;
    private int opmode;

    public void setParameters(String keyFile, String mode) {
        this.keyFile = keyFile;
        this.mode = mode;
    }

    public RSACipher(int opmode) {
        this.opmode = opmode;
    }

    @Override
    public byte[] mix(byte[] byteArray, byte[] byteArray2) {

        try {
            // get a DES cipher object and print the provider
            Cipher cipher = Cipher.getInstance("RSA/" + mode + "/PKCS1Padding");
            System.out.println(cipher.getProvider().getInfo());

            System.out.println("Ciphering ...");
            if(this.opmode == Cipher.DECRYPT_MODE) {
                do_decrypt(cipher);
            } else {
                do_encrypt(cipher);
            }

            
            return cipher.doFinal(b);

        } catch (Exception e) {
            // Pokemon exception handling!
            e.printStackTrace();
        }

        return null;

    }

    private void do_decrypt(Cipher cipher) throws Exception {
        PrivateKey key = getPrivateKey();
        if(!mode.equals("ECB")) {
            // look! A null IV!
            cipher.init(this.opmode, key, new IvParameterSpec(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
        } else {
            cipher.init(this.opmode, key);
        }
    }

    private void do_encrypt(Cipher cipher) throws Exception {
        PublicKey key = getPublicKey();
        if(!mode.equals("ECB")) {
            // look! A null IV!
            cipher.init(this.opmode, key, new IvParameterSpec(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
        } else {
            cipher.init(this.opmode, key);
        }
    }

    private PublicKey getPublicKey() throws Exception {
        byte[] key = Files.readAllBytes(Paths.get(this.keyFile));

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);

        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePublic(keySpec);
    }

    private PrivateKey getPrivateKey() throws Exception {
        byte[] key = Files.readAllBytes(Paths.get(this.keyFile));

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);

        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePrivate(keySpec);
    }
}
