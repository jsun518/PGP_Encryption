import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
//import org.jdamico.bc.openpgp.utils.PgpHelper;
//import org.jdamico.bc.openpgp.utils.RSAKeyPairGenerator;
import org.junit.Test;


public class TestBCOpenPGP {

	private boolean isArmored = false;
	private String id = "flowserve";
	private String passwd = "Flowserve$123";
	private boolean integrityCheck = true;


	private String pubKeyFile = "C:\\git_code\\public_key";
	private String privKeyFile = "C:\\git_code\\private_key";

	private String plainTextFile = "C:\\git_code\\test_encryption.txt"; //create a text file to be encripted, before run the tests
	private String multiplePlainTextFile = "C:\\git_code\\testencryptfolder\\test1.txt";
	private String cipherTextFile = "C:\\git_code\\test_encrypted";
	private String decPlainTextFile = "C:\\git_code\\test_decrypted";
	//private String signatureFile = "/tmp/signature.txt";

	public void main() throws IOException, NoSuchProviderException, PGPException {
		encrypt();
	}


	@Test
	public void genKeyPair() throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {

		RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();

		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator    kpg = KeyPairGenerator.getInstance("RSA", "BC");

		kpg.initialize(1024);

		KeyPair                    kp = kpg.generateKeyPair();

		FileOutputStream    out1 = new FileOutputStream(privKeyFile);
		FileOutputStream    out2 = new FileOutputStream(pubKeyFile);

		rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(), isArmored);


	}

	@Test
	public void encrypt() throws NoSuchProviderException, IOException, PGPException{
		FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
		FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
		PgpHelper.getInstance().encryptFile(cipheredFileIs, plainTextFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
		cipheredFileIs.close();
		pubKeyIs.close();
	}

	@Test
	public void encryptMultipleFiles() throws NoSuchProviderException, IOException, PGPException{
		List<String> result = Arrays.asList(multiplePlainTextFile.split("\\s*,\\s*"));
		for (int i = 0; i < result.size(); i++) {
			FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
			FileOutputStream cipheredFileIs = new FileOutputStream(result.get(i)+"ENCRYPTED");
			PgpHelper.getInstance().encryptFile(cipheredFileIs, result.get(i), PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
			cipheredFileIs.close();
			pubKeyIs.close();
		}
		//FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
	}

	@Test
	public void encryptFolder() throws NoSuchProviderException, IOException, PGPException{

		String cipherDirectory = "C:\\git_code\\testencryptfolder";
		String cipherOutputDir = "C:\\git_code\\testencryptoutputfolder";
		File folder = new File(cipherDirectory);
		File[] listOfFiles = folder.listFiles();

		for (File file : listOfFiles) {
			FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
			String FileName=file.getName();
			FileOutputStream fos= new FileOutputStream(cipherOutputDir+"/"+FileName+"_encrypte.csv");
			PgpHelper.getInstance().encryptFile(fos, cipherDirectory+"/"+FileName, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
			fos.close();
			pubKeyIs.close();
		}

		//pubKeyIs.close();
		//FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
		//PgpHelper.getInstance().encryptFile(cipheredFileIs, plainTextFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);


	}

	/**@Test
	public void decrypt() throws Exception{

		FileInputStream cipheredFileIs = new FileInputStream(cipherTextFile);
		FileInputStream privKeyIn = new FileInputStream(privKeyFile);
		FileOutputStream plainTextFileIs = new FileOutputStream(decPlainTextFile);
		PgpHelper.getInstance().decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray());
		cipheredFileIs.close();
		plainTextFileIs.close();
		privKeyIn.close();
	}

	/**@Test
	public void signAndVerify() throws Exception{
	FileInputStream privKeyIn = new FileInputStream(privKeyFile);
	FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
	FileInputStream plainTextInput = new FileInputStream(plainTextFile);
	FileOutputStream signatureOut = new FileOutputStream(signatureFile);

	byte[] bIn = PgpHelper.getInstance().inputStreamToByteArray(plainTextInput);
	byte[] sig = PgpHelper.getInstance().createSignature(plainTextFile, privKeyIn, signatureOut, passwd.toCharArray(), true);
	PgpHelper.getInstance().verifySignature(plainTextFile, sig, pubKeyIs);
	}**/

}
