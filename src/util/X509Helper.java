/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package util;

import java.io.ByteArrayInputStream;
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
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import sun.security.x509.InhibitAnyPolicyExtension;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.X509CertImpl;
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
                keyStoreInstance.load(null,null);
            } catch (IOException | KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException e) {
                Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, e);
            } 
        }
        return keyStoreInstance;
    }
    
     public Enumeration<String> loadLocalKeystore(){
        try {
            KeyStore keyStore = getKeyStoreInstance();
            FileInputStream fileInputStream = new FileInputStream(Constants.keyStoreName);
            keyStore.load(fileInputStream, Constants.keyStorePassword.toCharArray());
            fileInputStream.close();
            
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
            Constants.selectedKeyPair = name;
            
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
    
    public boolean removeKeypair(String name) {
        try {
            if( getKeyStoreInstance().containsAlias(name)) {
                getKeyStoreInstance().deleteEntry(name);
                storeKeyStore();
            }
            return true;
        } catch (KeyStoreException ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public boolean importKeypair(String name, String file_name, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            FileInputStream fileInputStream = new FileInputStream(file_name);
            keyStore.load(fileInputStream, password.toCharArray());
            fileInputStream.close();
            
            Certificate certificates[] = keyStore.getCertificateChain(Constants.keyPairName);
            Key key = keyStore.getKey(Constants.keyPairName, password.toCharArray());
            
            if(!getKeyStoreInstance().containsAlias(name)) {
                getKeyStoreInstance().setKeyEntry(name, key, Constants.keyStorePassword.toCharArray(), certificates);
                storeKeyStore();
                return true;
            }
            
        } catch (Exception ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public boolean exportKeypair(String name, String file_name, String password) {
        try {
            ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(Constants.keyStorePassword.toCharArray());
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            keyStore.load(null,null);
            
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) getKeyStoreInstance().getEntry(name, protectionParameter);
            Certificate certificates[] = privateKeyEntry.getCertificateChain();
            
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            keyStore.setKeyEntry(Constants.keyPairName, privateKey, password.toCharArray(), certificates);
            
            FileOutputStream fileOutputStream = new FileOutputStream(file_name+".p12");
            keyStore.store(fileOutputStream, password.toCharArray());
            fileOutputStream.close();
            
        } catch (Exception ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public boolean signCertificate(String issuer, String algorithm) {
        try {
            ProtectionParameter protectionParameter = new PasswordProtection(Constants.keyStorePassword.toCharArray());
            PrivateKeyEntry issuerEntry = (PrivateKeyEntry) getKeyStoreInstance().getEntry(issuer, protectionParameter);
            PrivateKeyEntry subjectEntry = (PrivateKeyEntry) getKeyStoreInstance().getEntry(Constants.selectedKeyPair, protectionParameter);
            
            X509Certificate certificate = signCertificate(subjectEntry, issuerEntry);
            Certificate [] certificates = {certificate};
            
            getKeyStoreInstance().deleteEntry(Constants.selectedKeyPair);
            getKeyStoreInstance().setKeyEntry(Constants.selectedKeyPair, subjectEntry.getPrivateKey(), Constants.keyStorePassword.toCharArray(), certificates);
            storeKeyStore();
            
            return true;
        } catch (Exception ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        } 
        return false;
    }
    
    public boolean importCertificate(File file, String string) {
        return false;
    }
    
    public boolean exportCertificate(File file, int i) {
        return false;
    }
    
    public String getIssuer(String name) {
        try {
            ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(Constants.keyStorePassword.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) getKeyStoreInstance().getEntry(name, protectionParameter);
            X509Certificate certificate = (X509Certificate) privateKeyEntry.getCertificate();
            
            return certificate.getSubjectDN().toString();
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        } 
        return null;
    }
    
    public String getIssuerPublicKeyAlgorithm(String name) {
        try {
            X509Certificate certificate = (X509Certificate) getKeyStoreInstance().getCertificate(name);
            return certificate.getSigAlgName();
        } catch (KeyStoreException ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public int getRSAKeyLength(String name) {
        try {
            X509Certificate certificate = (X509Certificate) getKeyStoreInstance().getCertificate(name);
        } catch (KeyStoreException ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        } 
        return 0;
    }

    public List<String> getIssuers(String name) {
        try {
          List<String> result = new ArrayList();
          Enumeration<String> aliases = getKeyStoreInstance().aliases();
          while (aliases.hasMoreElements()) {
              String alias = aliases.nextElement();
              if(alias.compareTo(name) != 0) {
//                X509Certificate certificate = (X509Certificate) getKeyStoreInstance().getCertificate(alias);
                result.add(alias);
              }
          }
          
          if(result.isEmpty()) return null;
          return result;
        } catch (Exception ex) {
          Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public boolean generateCSR(String name) {
        try {
            if(getKeyStoreInstance().containsAlias(name)) {
                ProtectionParameter protectionParameter = new PasswordProtection(Constants.keyStorePassword.toCharArray());
                PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) getKeyStoreInstance().getEntry(name, protectionParameter);
                X509Certificate certificate = (X509Certificate) privateKeyEntry.getCertificate();
                PrivateKey privateKey = privateKeyEntry.getPrivateKey();
                String algorithm = certificate.getSigAlgName().contains("RSA") ? certificate.getSigAlgName() : "MD2withRSA"  ;
                PKCS10CertificationRequest pkcs10Request = new PKCS10CertificationRequest(algorithm, certificate.getSubjectX500Principal(), certificate.getPublicKey(), null, privateKey);
                Constants.CSR = pkcs10Request;
                
                return true;
            }
        } catch (Exception ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        }
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
            
            //KEY USAGE
            if(Constants.access.isCritical(2)) {
                
                boolean[] bools = Constants.access.getKeyUsage();
                int temp = 0;
                
                if (bools[0]) temp = temp | KeyUsage.digitalSignature;
                if (bools[1]) temp = temp | KeyUsage.nonRepudiation;
                if (bools[2]) temp = temp | KeyUsage.keyEncipherment;
                if (bools[3]) temp = temp | KeyUsage.dataEncipherment;
                if (bools[4]) temp = temp | KeyUsage.keyAgreement;
                if (bools[5]) temp = temp | KeyUsage.keyCertSign;
                if (bools[6]) temp = temp | KeyUsage.cRLSign;
                if (bools[7]) temp = temp | KeyUsage.encipherOnly;
                if (bools[8]) temp = temp | KeyUsage.decipherOnly;
                
                KeyUsage keyUsage = new KeyUsage(temp);
                certGen.addExtension(Extension.keyUsage, Constants.access.isCritical(2), keyUsage);
            }
            
            //SUBJECT ALTERNATIVE NAMES
            if (Constants.access.getAlternativeName(5).length > 0) {
                List<GeneralName> names = new ArrayList();
                for(String name: Constants.access.getAlternativeName(5)) {
                  GeneralName altName = new GeneralName(GeneralName.dNSName, name);
                  names.add(altName);
                }
                if (Constants.access.isCritical(5)) {
                    names.add(new GeneralName(GeneralName.dNSName, "desibratemoj"));
                }
                GeneralName [] listToArray = new GeneralName[names.size()];
                names.toArray(listToArray);
                GeneralNames subjectAltName = new GeneralNames(listToArray);
                certGen.addExtension(Extension.subjectAlternativeName, Constants.access.isCritical(5), subjectAltName); 
            }
            
            //Inhibit any policy        
             if (Constants.access.getInhibitAnyPolicy()) {
                InhibitAnyPolicyExtension inhibitAnyPolicyExtension = new InhibitAnyPolicyExtension(new Integer(Constants.access.getSkipCerts()));
                certGen.addExtension(X509Extensions.InhibitAnyPolicy, true, inhibitAnyPolicyExtension.getExtensionValue());
             }
            
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
            
            Enumeration<String> ldaps = ldapName.getAll();
            
            while(ldaps.hasMoreElements()) {
                String s = ldaps.nextElement();
                String[] strs = s.split("=");
                switch(strs[0]) {
                    case ("C"):  Constants.access.setSubjectCountry(strs[1]); break;
                    case ("ST"): Constants.access.setSubjectState(strs[1]); break;
                    case ("L"):  Constants.access.setSubjectLocality(strs[1]); break;
                    case ("O"):  Constants.access.setSubjectOrganization(strs[1]); break;
                    case ("OU"): Constants.access.setSubjectOrganizationUnit(strs[1]); break;
                    case ("CN"): Constants.access.setSubjectCommonName(strs[1]); break;                   
                }
            }
            
            Constants.access.setVersion((certificate.getVersion())==3?2:1);
            Constants.access.setSerialNumber(certificate.getSerialNumber().toString());
            Constants.access.setPublicKeyParameter(certificate.getPublicKey().toString());
            Constants.access.setNotBefore(certificate.getNotBefore());
            Constants.access.setNotAfter(certificate.getNotAfter());
            
            //EXTENSION FIELDS
            
            //SUBJECT ALTERNATIVE NAME
            Collection collection = certificate.getSubjectAlternativeNames();

            if(collection != null) {
                String subjectAlternativeNames = "";
                for (Iterator iterator = collection.iterator(); iterator.hasNext();) {  
                    List<Object> nameTypePair = (List<Object>) iterator.next();   
                    Integer typeOfAlternativeName = (Integer)nameTypePair.get(0);
                    String alternativeName = (String) nameTypePair.get(1);
                    if (!alternativeName.equals("desibratemoj")) {
                        subjectAlternativeNames += alternativeName;
                    } else {
                        Constants.access.setCritical(5, true);
                    }
                }
                Constants.access.setAlternativeName(5, subjectAlternativeNames);
            }
            
            //KEY USAGE CRITICAL
            if (certificate.getKeyUsage() != null) {
                Constants.access.setKeyUsage(certificate.getKeyUsage());
                Constants.access.setCritical(2, true);
            }
            
            //Inhibit any policy
            byte[] extVal = certificate.getExtensionValue(Extension.inhibitAnyPolicy.toString());
            if (extVal != null) {
              Object obj = new ASN1InputStream(extVal).readObject();
              extVal = ((DEROctetString) obj).getOctets();
              obj = new ASN1InputStream(extVal).readObject();
              Constants.access.setInhibitAnyPolicy(true);
              Constants.access.setSkipCerts(obj.toString());
              Constants.access.setCritical(10, true);
            }
            
            //ISSUER FIELDS
            Principal issuerDN = certificate.getIssuerDN();
            String issuerString = issuerDN.toString().replace(" ", "");
            Constants.access.setIssuer(issuerString);
            Constants.access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
            
            return 0;
        } catch (Exception ex) {
            Logger.getLogger(X509Helper.class.getName()).log(Level.SEVERE, null, ex);
        } 
        return -1;
    }

    private X509Certificate signCertificate(KeyStore.PrivateKeyEntry subjectEntry, KeyStore.PrivateKeyEntry issuerEntry) throws Exception {
        
        X509Certificate subjectCert = (X509Certificate) subjectEntry.getCertificate();
        X509Certificate issuerCert = (X509Certificate) issuerEntry.getCertificate();
        
        KeyPair keyPair = new KeyPair(subjectCert.getPublicKey(), issuerEntry.getPrivateKey());

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(subjectCert.getSerialNumber());
        certGen.setIssuerDN(new X500Principal(issuerCert.getSubjectDN().toString()));
        certGen.setNotBefore(subjectCert.getNotBefore());
        certGen.setNotAfter(subjectCert.getNotAfter());
        certGen.setSubjectDN(new X500Principal(subjectCert.getSubjectDN().toString()));
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm(subjectCert.getSigAlgName());

        //KEY USAGE
        if(issuerCert.getKeyUsage() != null) {

            boolean[] bools = issuerCert.getKeyUsage();
            int temp = 0;

            if (bools[0]) temp = temp | KeyUsage.digitalSignature;
            if (bools[1]) temp = temp | KeyUsage.nonRepudiation;
            if (bools[2]) temp = temp | KeyUsage.keyEncipherment;
            if (bools[3]) temp = temp | KeyUsage.dataEncipherment;
            if (bools[4]) temp = temp | KeyUsage.keyAgreement;
            if (bools[5]) temp = temp | KeyUsage.keyCertSign;
            if (bools[6]) temp = temp | KeyUsage.cRLSign;
            if (bools[7]) temp = temp | KeyUsage.encipherOnly;
            if (bools[8]) temp = temp | KeyUsage.decipherOnly;

            KeyUsage keyUsage = new KeyUsage(temp);
            certGen.addExtension(Extension.keyUsage, true, keyUsage);
        }

        //SUBJECT ALTERNATIVE NAMES
        Collection collection = issuerCert.getSubjectAlternativeNames();
        if(collection != null) {
            List<GeneralName> names = new ArrayList();
            boolean isCritical = false;
            
            for (Iterator iterator = collection.iterator(); iterator.hasNext();) {  
                List<Object> nameTypePair = (List<Object>) iterator.next();   
                Integer typeOfAlternativeName = (Integer)nameTypePair.get(0);
                String alternativeName = (String) nameTypePair.get(1);
                if (!alternativeName.equals("desibratemoj")) {
                    GeneralName altName = new GeneralName(GeneralName.dNSName, alternativeName);
                    names.add(altName);
                } else {
                    isCritical = true;
                }
            }
            GeneralName [] listToArray = new GeneralName[names.size()];
            names.toArray(listToArray);
            GeneralNames subjectAltName = new GeneralNames(listToArray);
            certGen.addExtension(Extension.subjectAlternativeName, isCritical, subjectAltName); 
        }

        //Inhibit any policy        
        byte[] extVal = issuerCert.getExtensionValue(Extension.inhibitAnyPolicy.toString());
        if (extVal != null) {
            Object obj = new ASN1InputStream(extVal).readObject();
            extVal = ((DEROctetString) obj).getOctets();
            obj = new ASN1InputStream(extVal).readObject();
            InhibitAnyPolicyExtension inhibitAnyPolicyExtension = new InhibitAnyPolicyExtension(new Integer(obj.toString()));
            certGen.addExtension(X509Extensions.InhibitAnyPolicy, true, inhibitAnyPolicyExtension.getExtensionValue());
        }

        return certGen.generateX509Certificate(keyPair.getPrivate(), "BC");
    }
    
}
