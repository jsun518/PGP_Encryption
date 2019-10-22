//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class PgpHelper {

    private static PgpHelper INSTANCE = null;

    public static PgpHelper getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new PgpHelper();
        }
        return INSTANCE;
    }

    public PGPPublicKey readPublicKey(String filePath) {

        PGPPublicKey key = null;
        try (BufferedInputStream bis = new BufferedInputStream(PGPUtil.getDecoderStream(new FileInputStream(filePath)))) {

            PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(bis);
            Iterator rIt = pgpPub.getKeyRings();

            while (key == null && rIt.hasNext()) {
                PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
                Iterator kIt = kRing.getPublicKeys();

                while (key == null && kIt.hasNext()) {
                    PGPPublicKey k = (PGPPublicKey) kIt.next();
                    if (k.isEncryptionKey()) {
                        key = k;
                    }
                }
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException | IOException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        }

        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }

        return key;
    }

    public PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        if (pgpSecKey == null) {
            return null;
        } else {
            PBESecretKeyDecryptor a = (new JcePBESecretKeyDecryptorBuilder((new JcaPGPDigestCalculatorProviderBuilder()).setProvider("BC").build())).setProvider("BC").build(pass);
            return pgpSecKey.extractPrivateKey(a);
        }
    }

    public void decryptFile(String inFilePath, String outFilePath, String keyFilePath, char[] passwd) {

        Security.addProvider(new BouncyCastleProvider());

        try (BufferedInputStream in = new BufferedInputStream(PGPUtil.getDecoderStream(new FileInputStream(inFilePath)));
                BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outFilePath));
                BufferedInputStream keyIn = new BufferedInputStream(new FileInputStream(keyFilePath))) {

            PGPObjectFactory pgpF = new PGPObjectFactory(in);
            Object obj = pgpF.nextObject();
            PGPEncryptedDataList enc;
            if (obj instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) obj;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe;
            for (pbe = null; sKey == null && it.hasNext(); sKey = this.findSecretKey(keyIn, pbe.getKeyID(), passwd)) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
            }

            if (sKey == null) {
                throw new IllegalArgumentException("Secret key for message not found.");
            }

            PublicKeyDataDecryptorFactory b = (new JcePublicKeyDataDecryptorFactoryBuilder()).setProvider("BC").setContentProvider("BC").build(sKey);
            InputStream clear = pbe.getDataStream(b);
            PGPObjectFactory plainFact = new PGPObjectFactory(clear);
            Object message = plainFact.nextObject();
            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
                message = pgpFact.nextObject();
            }

            if (!(message instanceof PGPLiteralData)) {
                if (message instanceof PGPOnePassSignatureList) {
                    throw new PGPException("Encrypted message contains a signed message - not literal data.");
                } else {
                    throw new PGPException("Message is not a simple encrypted file - type unknown.");
                }
            } else {
                PGPLiteralData ld = (PGPLiteralData) message;
                InputStream unc = ld.getInputStream();

                int ch;
                while ((ch = unc.read()) >= 0) {
                    out.write(ch);
                }

                if (pbe.isIntegrityProtected() && !pbe.verify()) {
                    throw new PGPException("Message failed integrity check");
                }
            }

        } catch (FileNotFoundException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException | IOException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    
    private void encryptFile_Armored(String outFileName, String inFileName, PGPPublicKey encKey, boolean withIntegrityCheck) {
        Security.addProvider(new BouncyCastleProvider());

        try (ArmoredOutputStream out = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(outFileName)))) {
           
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(1);
            PGPUtil.writeFileToLiteralData(comData.open(bOut), 'b', new File(inFileName));
            comData.close();
            JcePGPDataEncryptorBuilder c = (new JcePGPDataEncryptorBuilder(3)).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");
            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);
            JcePublicKeyKeyEncryptionMethodGenerator d = (new JcePublicKeyKeyEncryptionMethodGenerator(encKey)).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());
            cPk.addMethod(d);
            byte[] bytes = bOut.toByteArray();
            
            try (OutputStream cOut = cPk.open((OutputStream) out, (long) bytes.length)) {
                cOut.write(bytes);
            } catch (IOException | PGPException ex) {
                Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
            }

        } catch (FileNotFoundException ex) { 
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    
    public void encryptFile(String outFileName, String inFileName, PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck) {
        
        if (armor) {
            this.encryptFile_Armored(outFileName, inFileName, encKey, withIntegrityCheck);
            return;
        }
        
        Security.addProvider(new BouncyCastleProvider());
        try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outFileName))) {

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(1);
            PGPUtil.writeFileToLiteralData(comData.open(bOut), 'b', new File(inFileName));
            comData.close();
            JcePGPDataEncryptorBuilder c = (new JcePGPDataEncryptorBuilder(3)).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");
            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);
            JcePublicKeyKeyEncryptionMethodGenerator d = (new JcePublicKeyKeyEncryptionMethodGenerator(encKey)).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());
            cPk.addMethod(d);
            byte[] bytes = bOut.toByteArray();
            //out.close();
            
            try (OutputStream cOut = cPk.open((OutputStream) out, (long) bytes.length)) {
                cOut.write(bytes);
            } catch (IOException | PGPException ex) {
                Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
            }

        } catch (FileNotFoundException ex) { 
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public byte[] inputStreamToByteArray(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[1024];

        int nRead;
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        buffer.flush();
        return buffer.toByteArray();
    }

    public void verifySignature(String fileName, byte[] b, InputStream keyIn) throws GeneralSecurityException, IOException, PGPException {
        PGPObjectFactory pgpFact = new PGPObjectFactory(b);
        PGPSignatureList p3 = null;
        Object o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData) o;
            pgpFact = new PGPObjectFactory(c1.getDataStream());
            p3 = (PGPSignatureList) pgpFact.nextObject();
        } else {
            p3 = (PGPSignatureList) o;
        }

        PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
        InputStream dIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSignature sig = p3.get(0);
        PGPPublicKey key = pgpPubRingCollection.getPublicKey(sig.getKeyID());
        sig.init((new JcaPGPContentVerifierBuilderProvider()).setProvider(new BouncyCastleProvider()), key);

        int ch;
        while ((ch = dIn.read()) >= 0) {
            sig.update((byte) ch);
        }

        dIn.close();
        if (sig.verify()) {
            System.out.println("signature verified.");
        } else {
            System.out.println("signature verification failed.");
        }

    }

    public PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input));
        Iterator keyRingIter = pgpSec.getKeyRings();

        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();
            Iterator keyIter = keyRing.getSecretKeys();

            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    public byte[] createSignature(String fileName, InputStream keyIn, OutputStream out, char[] pass, boolean armor) throws GeneralSecurityException, IOException, PGPException {
        PGPSecretKey pgpSecKey = this.readSecretKey(keyIn);
        PGPPrivateKey pgpPrivKey = pgpSecKey.extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).setProvider(new BouncyCastleProvider()).build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator((new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), 2)).setProvider(new BouncyCastleProvider()));
        sGen.init(0, pgpPrivKey);
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(byteOut);
        BCPGOutputStream bOut = new BCPGOutputStream(byteOut);
        BufferedInputStream fIn = new BufferedInputStream(new FileInputStream(fileName));

        int ch;
        while ((ch = fIn.read()) >= 0) {
            sGen.update((byte) ch);
        }

        aOut.endClearText();
        fIn.close();
        sGen.generate().encode(bOut);
        if (armor) {
            aOut.close();
        }

        return byteOut.toByteArray();
    }
}
