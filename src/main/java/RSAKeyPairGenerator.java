
import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class RSAKeyPairGenerator {

    public KeyPair genKeyPair(String algo1, String algo2, int keySize) {
        KeyPair kp = null;
        try {
            Security.addProvider(new BouncyCastleProvider()); // ???????
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo1, algo2);
            kpg.initialize(keySize);
            kp = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kp;
    }

    public PGPKeyPair genPGPKeyPair(KeyPair kp) {
        PGPKeyPair kp_PGP = null;
        try {
            RSAPrivateCrtKey rsK = (RSAPrivateCrtKey) kp.getPrivate();
            RSASecretBCPGKey privPk = new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
            PGPPublicKey a = (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, kp.getPublic(), new Date()));
            PGPPrivateKey b = new PGPPrivateKey(a.getKeyID(), a.getPublicKeyPacket(), privPk);
            kp_PGP = new PGPKeyPair(a, b);
        } catch (PGPException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kp_PGP;
    }

    public PGPSecretKey genPGPsecretKey(PGPKeyPair kp, String identity, char[] passPhrase) {
        PGPSecretKey secretKey = null;
        try {
            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            secretKey = new PGPSecretKey(
                    PGPSignature.DEFAULT_CERTIFICATION,
                    kp,
                    identity,
                    sha1Calc,
                    null,
                    null,
                    new JcaPGPContentSignerBuilder(kp.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                    new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase)
            );
        } catch (PGPException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return secretKey;
    }

    private boolean exportKeyPair_Armored(PGPSecretKey secretKey, String secretPath, String publicPath) {
        try (ArmoredOutputStream bos_Secret = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(secretPath)));
                ArmoredOutputStream bos_Public = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(publicPath)));) {

            secretKey.encode(bos_Secret);
            secretKey.getPublicKey().encode(bos_Public);

        } catch (FileNotFoundException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        } catch (IOException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
        return true;
    }

    public boolean exportKeyPair(PGPSecretKey secretKey, String secretPath, String publicPath, boolean isArmored) {

        if (isArmored) {
            return exportKeyPair_Armored(secretKey, secretPath, publicPath);
        }

        try (BufferedOutputStream bos_Secret = new BufferedOutputStream(new FileOutputStream(secretPath));
                BufferedOutputStream bos_public = new BufferedOutputStream(new FileOutputStream(publicPath));) {

            secretKey.encode(bos_Secret);
            secretKey.getPublicKey().encode(bos_public);

        } catch (FileNotFoundException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        } catch (IOException ex) {
            Logger.getLogger(PgpHelper.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }

        return true;
    }

    public boolean generateAndExportKeys(String algo1, String algo2, int keySize, String identity, char[] passPhrase, String secretPath, String publicPath, boolean isArmored) {
        KeyPair kp = this.genKeyPair(algo1, algo2, 1024);
        PGPKeyPair pgpKP = genPGPKeyPair(kp);
        PGPSecretKey secretKey = this.genPGPsecretKey(pgpKP, identity, passPhrase);
        return this.exportKeyPair(secretKey, secretPath, publicPath, isArmored);
    }

}
