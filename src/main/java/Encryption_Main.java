import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;

public class Encryption_Main {
    static Integer gen_key_pair = Integer.valueOf(System.getProperty("GEN_KEY_PAIR"));
    static Integer encrypt = Integer.valueOf(System.getProperty("ENCRYPTION"));
    static Integer decrypt = Integer.valueOf(System.getProperty("DECRYPTION"));

    public static void main(String[] args) throws Exception {
        if (gen_key_pair == null)
        {gen_key_pair=0;}

        if (encrypt == null)
        {encrypt=0;}

        if (decrypt == null)
        {decrypt=0;}

        System.out.println("Program starting shortly...");
        if (gen_key_pair==1){
            String id = System.getProperty("ID");
            String passwd = System.getProperty("PWD");
            boolean isArmored = true;
            RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(1024);
            KeyPair kp = kpg.generateKeyPair();

            FileOutputStream out1 = new FileOutputStream(System.getProperty("GEN_PRIV_KEY"));
            FileOutputStream out2 = new FileOutputStream(System.getProperty("GEN_PUB_KEY"));
            if (id == null){id="default";}
            if (passwd == null){passwd="default";}
            rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(), isArmored);
            System.out.println("Key pairs created successfully!!!");
        }
        else {
            System.out.println("Key pair generation is not needed.");
        }

        if (encrypt==1){
            String pubKeyFile = System.getProperty("EXISTPUBKEYFILE");
            String cipherTextFile = System.getProperty("CIPHEREDFILEOUTPUT");
            String originalFile = System.getProperty("ORIGINALFILEINPUT");
            boolean integrityCheck=true;
            boolean isArmored = false;

            FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
            FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
            PgpHelper.getInstance().encryptFile(cipheredFileIs, originalFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
            cipheredFileIs.close();
            pubKeyIs.close();
            System.out.println("File encrypted successfully!!! The file is created as "+cipherTextFile+"... Please verify...");
        }
        else {
            System.out.println("Encryption is not needed.");
        }

        if (decrypt==1){
            String cipherTextFile = System.getProperty("CIPHEREDFILEINPUT");
            String privKeyFile = System.getProperty("PRIVATEKEYFILE");
            String decPlainTextFile = System.getProperty("DECRYPTEDFILEOUTPUT");
            String passwd = System.getProperty("PWD");

            FileInputStream cipheredFileIs = new FileInputStream(cipherTextFile);
            FileInputStream privKeyIn = new FileInputStream(privKeyFile);
            FileOutputStream plainTextFileIs = new FileOutputStream(decPlainTextFile);
            PgpHelper.getInstance().decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray());
            cipheredFileIs.close();
            plainTextFileIs.close();
            privKeyIn.close();
            System.out.println("File decrypted successfully!!! The file is created as "+decPlainTextFile+"... Please verify...");
        }
        else {System.out.println("Decryption is not needed.");
        }

        System.out.println("Program finished successfully!!!!!");
    }
}
