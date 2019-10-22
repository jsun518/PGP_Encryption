
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;

import org.junit.Before;
import org.junit.Test;

public class TestBCOpenPGP {

    private boolean isArmored = false;
    private String id = "flowserve";
    private String passwd = "Flowserve$123";
    private boolean integrityCheck = true;


    private final String testDir = "TestFiles";

    //key generation parameters
    private final String keysDir = testDir + "\\Keys";
    private final String pubKeyFile = keysDir + "\\public_key";
    private final String privKeyFile = keysDir + "\\private_key";

    //single plaintext 
    private final String plainTextFile_Dir = testDir + "\\plainTextFileTest";
    private final String plainTextFile = plainTextFile_Dir + "\\plainTextFile.txt";
    private final String plainTextFile_msg = "plainTextFile test...";
    private final String plainTextFile_encrypted = plainTextFile_Dir + "\\plainTextFile_encrypted";
    private final String plainTextFile_decrypted = plainTextFile_Dir + "\\plainTextFile_decrypted";

    //multiplePlainTextFile 
    private final String multiplePlainTextFile_Dir = testDir + "\\multiplePlainTextFileTest";
    private final String multiplePlainTextFile_test1 = multiplePlainTextFile_Dir + "\\test1.txt";
    private final String multiplePlainTextFile_test2 = multiplePlainTextFile_Dir + "\\test2.txt";
    private final String multiplePlainTextFile_test1_msg = "test#1...";
    private final String multiplePlainTextFile_test2_msg = "test#2...";
    private final String multiplePlainTextFile = multiplePlainTextFile_test1 + "," + multiplePlainTextFile_test2;

    //Folder
    private final String folderTestDir = testDir + "\\folderTest";
    private final String folderInput = folderTestDir + "\\input";
    private final String folderOutput = folderTestDir + "\\output";
    private final String folderTest_file1 = folderInput + "\\test1.txt";
    private final String folderTest_file2 = folderInput + "\\test2.txt";
    private final String folderTest_file1_msg = "test#1...";
    private final String folderTest_file2_msg = "test#2...";

    public void writetoFile(String fp, String msg) {
        try (BufferedOutputStream writer = new BufferedOutputStream(new FileOutputStream(fp))) {
            writer.write(msg.getBytes());
        } catch (IOException ex) {
            Logger.getLogger(TestBCOpenPGP.class.getName()).log(Level.SEVERE, null, ex);
            throw new IllegalArgumentException("Test directory creation FAILED: " + fp + "......");
        }
    }

    @Before
    public void createOutputDir() {
        
        //cleanup last test data
        if (new File(this.testDir).exists()) {
            try {
                FileUtils.deleteDirectory(new File(this.testDir));
            } catch (IOException ex) {
                Logger.getLogger(TestBCOpenPGP.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        if (!new File(this.testDir).mkdir()
                || !new File(this.keysDir).mkdir()
                || !new File(this.plainTextFile_Dir).mkdir()
                || !new File(this.multiplePlainTextFile_Dir).mkdir()
                || !new File(this.folderTestDir).mkdir()
                || !new File(this.folderInput).mkdir()
                || !new File(this.folderOutput).mkdir()) {
            throw new IllegalArgumentException("Test directory creation FAILED");
        }
        writetoFile(this.plainTextFile, this.plainTextFile_msg);
        writetoFile(this.multiplePlainTextFile_test1, this.multiplePlainTextFile_test1_msg);
        writetoFile(this.multiplePlainTextFile_test2, this.multiplePlainTextFile_test2_msg);
        writetoFile(this.folderTest_file1, this.folderTest_file1_msg);
        writetoFile(this.folderTest_file2, this.folderTest_file2_msg);
    }

    @Test
    public void run_ALL_TESTS() {
        singleFile_TEST();
        mutiFile_TEST();
        folder_TEST();
    }


    public void singleFile_TEST() {
        Encryption_Main em = new Encryption_Main();
        em.genKeyPair(privKeyFile, pubKeyFile, id, passwd);

        //encryptFile(String outFileName, String inFileName, String pubKeyFile, boolean armored, boolean integrityCheck)
        em.encryptFile(plainTextFile_encrypted, plainTextFile, pubKeyFile, isArmored, integrityCheck);

        //decrypt(String inFileName, String outFileName, String privKeyFileName, String passwd)
        em.decrypt(plainTextFile_encrypted, plainTextFile_decrypted, privKeyFile, passwd);

        new File(this.pubKeyFile).delete();
        new File(this.privKeyFile).delete();
    }

    public void mutiFile_TEST() {
        Encryption_Main em = new Encryption_Main();
        em.genKeyPair(privKeyFile, pubKeyFile, id, passwd);
        //encryptFiles(String inFileNames, String suffix, String pubKeyFile, boolean armored, boolean integrityCheck)
        List<String> list = em.encryptFiles(multiplePlainTextFile, "ENCRYPT", pubKeyFile, isArmored, integrityCheck);
        for (String fp : list) {
            //decrypt(String inFileName, String outFileName, String privKeyFileName, String passwd)
            em.decrypt(fp, fp + "_decrypted", privKeyFile, passwd);
        }

        new File(this.pubKeyFile).delete();
        new File(this.privKeyFile).delete();
    }

    public void folder_TEST() {
        Encryption_Main em = new Encryption_Main();
        em.genKeyPair(privKeyFile, pubKeyFile, id, passwd);
        //encryptFolder(String outDir, String inDir, String suffix, String pubKeyFile, boolean armored, boolean integrityCheck)
        em.encryptFolder(folderOutput, folderInput, "_encrypte.csv", pubKeyFile, isArmored, integrityCheck);

        new File(this.pubKeyFile).delete();
        new File(this.privKeyFile).delete();
    }

//    @Test
//    public void encryptMultipleFiles() throws NoSuchProviderException, IOException, PGPException {
//        List<String> result = Arrays.asList(multiplePlainTextFile.split("\\s*,\\s*"));
//        for (int i = 0; i < result.size(); i++) {
//            FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
//            FileOutputStream cipheredFileIs = new FileOutputStream(result.get(i) + "ENCRYPTED");
//            PgpHelper.getInstance().encryptFile(cipheredFileIs, result.get(i), PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
//            cipheredFileIs.close();
//            pubKeyIs.close();
//        }
//        //FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
//    }
//
//    @Test
//    public void encryptFolder() throws NoSuchProviderException, IOException, PGPException {
//
//        String cipherDirectory = "C:\\git_code\\testencryptfolder";
//        String cipherOutputDir = "C:\\git_code\\testencryptoutputfolder";
//        File folder = new File(cipherDirectory);
//        File[] listOfFiles = folder.listFiles();
//
//        for (File file : listOfFiles) {
//            FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
//            String FileName = file.getName();
//            FileOutputStream fos = new FileOutputStream(cipherOutputDir + "/" + FileName + "_encrypte.csv");
//            PgpHelper.getInstance().encryptFile(fos, cipherDirectory + "/" + FileName, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
//            fos.close();
//            pubKeyIs.close();
//        }
    //pubKeyIs.close();
    //FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
    //PgpHelper.getInstance().encryptFile(cipheredFileIs, plainTextFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
//}
    /**
     * @Test public void signAndVerify() throws Exception{ FileInputStream
     * privKeyIn = new FileInputStream(privKeyFile); FileInputStream pubKeyIs =
     * new FileInputStream(pubKeyFile); FileInputStream plainTextInput = new
     * FileInputStream(plainTextFile); FileOutputStream signatureOut = new
     * FileOutputStream(signatureFile);
     *
     * byte[] bIn =
     * PgpHelper.getInstance().inputStreamToByteArray(plainTextInput); byte[]
     * sig = PgpHelper.getInstance().createSignature(plainTextFile, privKeyIn,
     * signatureOut, passwd.toCharArray(), true);
     * PgpHelper.getInstance().verifySignature(plainTextFile, sig, pubKeyIs); }*
     */
}
