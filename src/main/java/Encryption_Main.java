

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.openpgp.PGPPublicKey;

public class Encryption_Main {

    public static void main(String[] args) throws Exception {

        Integer gen_key_pair = Integer.valueOf(System.getProperty("GEN_KEY_PAIR"));
        Integer encrypt = Integer.valueOf(System.getProperty("ENCRYPTION"));
        Integer decrypt = Integer.valueOf(System.getProperty("DECRYPTION"));

        Encryption_Main em = new Encryption_Main();

        if (gen_key_pair == null) {
            gen_key_pair = 0;
        }

        if (encrypt == null) {
            encrypt = 0;
        }

        if (decrypt == null) {
            decrypt = 0;
        }

        System.out.println("Program starting shortly...");
        if (gen_key_pair == 1) {
            String privateKeyPath = System.getProperty("GEN_PRIV_KEY");
            String publicKeyPath = System.getProperty("GEN_PUB_KEY");
            String id = System.getProperty("ID");
            String passwd = System.getProperty("PWD");
            em.genKeyPair(privateKeyPath, publicKeyPath, id, passwd);
        }

        if (encrypt == 1) {
            String pubKeyFile = System.getProperty("EXISTPUBKEYFILE");
            String cipherTextFile = System.getProperty("CIPHEREDFILEOUTPUT");
            String originalFile = System.getProperty("ORIGINALFILEINPUT");
            String cipherDirectory = System.getProperty("CIPHERDIR");
            String cipherOutputDir = System.getProperty("CIPHEROUTPUTDIR");
            boolean integrityCheck = true;
            boolean isArmored = false;

            if (cipherDirectory == null) {
                em.encryptFiles(originalFile, "ENCRYPT", pubKeyFile, isArmored, integrityCheck);
            } else {
                em.encryptFolder(cipherOutputDir, cipherDirectory, "_encrypte.csv", pubKeyFile, isArmored, integrityCheck);
            }
        }

        if (decrypt == 1) {
            String cipherTextFile = System.getProperty("CIPHEREDFILEINPUT");
            String privKeyFile = System.getProperty("PRIVATEKEYFILE");
            String decPlainTextFile = System.getProperty("DECRYPTEDFILEOUTPUT");
            String passwd = System.getProperty("PWD");
            em.decrypt(cipherTextFile, decPlainTextFile, privKeyFile, passwd);
        }
    }

    public void genKeyPair(String privateKeyPath, String publicKeyPath, String id, String passwd) {
        if (id == null) {
            id = "default";
        }
        if (passwd == null) {
            passwd = "default";
        }
        RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();
        rkpg.generateAndExportKeys("RSA", "BC", 1024, id, passwd.toCharArray(), privateKeyPath, publicKeyPath, true);
    }

    public void encryptFile(String outFileName, String inFileName, String pubKeyFile, boolean armored, boolean integrityCheck) {
        PGPPublicKey pubKey = PgpHelper.getInstance().readPublicKey(pubKeyFile);
        PgpHelper.getInstance().encryptFile(outFileName, inFileName, pubKey, armored, integrityCheck);
    }

    public List<String> encryptFiles(String inFileNames, String suffix, String pubKeyFile, boolean armored, boolean integrityCheck) {
        List<String> inputs = Arrays.asList(inFileNames.split("\\s*,\\s*"));
        List<String> newFiles = new ArrayList<>();
        for (String fp : inputs) {
            String encrypted_filePath = fp + suffix;
            if (fp.lastIndexOf('.') != -1) {
                int lastDot = fp.lastIndexOf('.');
                encrypted_filePath = fp.substring(0, lastDot) + suffix + fp.substring(lastDot);
            }
            newFiles.add(encrypted_filePath);
            this.encryptFile(encrypted_filePath, fp, pubKeyFile, armored, integrityCheck);
        }
        return newFiles;
    }

    public void encryptFolder(String outDir, String inDir, String suffix, String pubKeyFile, boolean armored, boolean integrityCheck) {
        File folder = new File(inDir);
        File[] listOfFiles = folder.listFiles();
        for (File file : listOfFiles) {
            String fileName = outDir + "\\" + file.getName() + suffix;
            this.encryptFile(fileName, file.getAbsoluteFile().toString(), pubKeyFile, armored, integrityCheck);
        }
    }

    public void decrypt(String inFileName, String outFileName, String privKeyFileName, String passwd) {
        PgpHelper.getInstance().decryptFile(inFileName, outFileName, privKeyFileName, passwd.toCharArray());
    }
}
