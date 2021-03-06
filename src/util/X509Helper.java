/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package util;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
/**
 *
 * @author sikimic
 */
public class X509Helper {
    
    private static KeyStore keyStoreInstance = null;
    private static X509Helper X509Instance = null;
    
    private X509Helper () {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    public static X509Helper getInstance() {
        if (X509Instance == null) {
            X509Instance = new X509Helper();
        }
        return X509Instance;
    }
    
    public static KeyStore getKeyStoreInstance() {
        if (keyStoreInstance == null) {
            try {
                keyStoreInstance = KeyStore.getInstance("BKS", "BC");  
            } catch (KeyStoreException | NoSuchProviderException e) {
                Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, e);
            } 
        }
        return keyStoreInstance;
    }
    
     public Enumeration<String> loadLocalKeystore(){
        try {
            KeyStore keyStore = getKeyStoreInstance();
            InputStream readStream = new FileInputStream(Constants.keyStoreName);
            keyStore.load(readStream, Constants.keyStorePassword.toCharArray());
            readStream.close();
            return keyStore.aliases();
        }  catch (Exception e) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, e);
        } 
        return null;
    }
     
    public void resetLocalKeystore() {
        try {
            getKeyStoreInstance().load(null,null);
            File keyStoreFile = new File(Constants.keyStoreName);
            keyStoreFile.delete();
          } catch (Exception ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
          }
    }
    
    public int loadKeypair(String name) {
        try {
            Certificate[] certificates = getKeyStoreInstance().getCertificateChain(name);
            X509Certificate certificate;

            if(certificates == null) {
              certificate = (X509Certificate) getKeyStoreInstance().getCertificate(name);
            } else {
              certificate = (X509Certificate) certificates[0];
            }
            
            return displayCertificate(certificate);
        } catch (KeyStoreException ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return 0;
    }
    
    public boolean saveKeypair(String name) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(Integer.parseInt(Constants.access.getPublicKeyParameter()));
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            X509Certificate cert = generateCertificate(keyPair, true, null);
            Certificate certs [] = {cert};
            getKeyStoreInstance().setKeyEntry(name, keyPair.getPrivate(), Constants.keyStorePassword.toCharArray(), certs);
            storeKeyStore();
            return true;
        } catch (Exception ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public boolean removeKeypair(String string) {
        try {
            if( getKeyStoreInstance().containsAlias(string)) {
                getKeyStoreInstance().deleteEntry(string);
                storeKeyStore();
            }
            return true;
        } catch (KeyStoreException ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public boolean importKeypair(String string, String string1, String string2) {
        return false;
    }
    
    public boolean exportKeypair(String string, String string1, String string2) {
        return false;
    }
    
    public boolean signCertificate(String string, String string1) {
        return false;
    }
    
    public boolean importCertificate(File file, String string) {
        return false;
    }
    
    public boolean exportCertificate(File file, int i) {
        return false;
    }
    
    public String getIssuer(String string) {
        return null;
    }
    
    public String getIssuerPublicKeyAlgorithm(String string) {
        return null;
    }
    
    public int getRSAKeyLength(String string) {
        return 0;
    }

    public List<String> getIssuers(String string) {
        return null;
    }
    
    public boolean generateCSR(String string) {
        return false;
    }

    //UTIL METHODS
    
    private X509Certificate generateCertificate(KeyPair keyPair , boolean selfSigned, Principal issuerDN) { 
        try {
            X500Principal x500Principal = new X500Principal("C=" + Constants.access.getSubjectCountry() +
                                                            ",ST=" + Constants.access.getSubjectState()+
                                                            ",L=" + Constants.access.getSubjectLocality()+
                                                            ",O=" + Constants.access.getSubjectOrganization()+
                                                            ",OU=" + Constants.access.getSubjectOrganizationUnit()+
                                                            ",CN=" + Constants.access.getSubjectCommonName());
            
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.setSerialNumber(new BigInteger(Constants.access.getSerialNumber()));
            certGen.setIssuerDN(selfSigned ? x500Principal : new X500Principal(issuerDN.toString()));
            certGen.setNotBefore(Constants.access.getNotBefore());
            certGen.setNotAfter(Constants.access.getNotAfter());
            certGen.setSubjectDN(x500Principal);
            certGen.setPublicKey(keyPair.getPublic());
            certGen.setSignatureAlgorithm(Constants.access.getPublicKeySignatureAlgorithm());
            
            //TODO:SET EXTENSIONS
            
//        certGen.addExtension(X509Extensions.BasicConstraints, uiParams.isExtensionBasicConstraintsIsCritical(), basicConstraint);

            return certGen.generateX509Certificate(keyPair.getPrivate(), "BC");
        } catch (Exception ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        } 
        return null;
    }
    
    private void storeKeyStore() {
        try {
          OutputStream writeStream;
          writeStream = new FileOutputStream(Constants.keyStoreName);
          getKeyStoreInstance().store(writeStream, Constants.keyStorePassword.toCharArray());
          writeStream.close();
        } catch (Exception ex) {
          Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private int displayCertificate (X509Certificate certificate) {
        try {
            //SUBJECT FIELDS
            Principal subjectDN = certificate.getSubjectDN();
            LdapName ldapName = new LdapName(subjectDN.toString());
            Constants.access.setSubjectCountry(ldapName.getRdn(0).getValue().toString());
            Constants.access.setSubjectState(ldapName.getRdn(1).getValue().toString());
            Constants.access.setSubjectLocality(ldapName.getRdn(2).getValue().toString());
            Constants.access.setSubjectOrganization(ldapName.getRdn(3).getValue().toString());
            Constants.access.setSubjectOrganizationUnit(ldapName.getRdn(4).getValue().toString());
            Constants.access.setSubjectCommonName(ldapName.getRdn(5).getValue().toString());
            Constants.access.setVersion((certificate.getVersion())==3?2:1);
            Constants.access.setSerialNumber(certificate.getSerialNumber().toString());
            Constants.access.setNotBefore(certificate.getNotBefore());
            Constants.access.setNotAfter(certificate.getNotAfter());
            
            //EXTENSION FIELDS
            
            //ISSUER FIELDS
            Principal issuerDN = certificate.getIssuerDN();
            String issuerString = issuerDN.toString().replace(" ", "");
//            Constants.access.setIssuer(issuerString);
            Constants.access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
            
            return 0;
        } catch (InvalidNameException ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return -1;
    }    
    
}
