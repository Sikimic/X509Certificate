/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import code.GuiException;
import code.X509;
import util.Constants;
import util.X509Helper;
import java.io.File;
import java.util.Enumeration;
import java.util.List;
import x509.v3.GuiV3;

/**
 *
 * @author sikimic
 */
public class MyCode extends x509.v3.CodeV3 {
    
    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
        Constants.access = super.access;
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
       return X509Helper.getInstance().loadLocalKeystore();
    }

    @Override
    public void resetLocalKeystore() {
        X509Helper.getInstance().resetLocalKeystore();
    }

    @Override
    public int loadKeypair(String string) {
        return X509Helper.getInstance().loadKeypair(string);
    }

    @Override
    public boolean saveKeypair(String string) {
        return X509Helper.getInstance().saveKeypair(string);
    }

    @Override
    public boolean removeKeypair(String string) {
        return X509Helper.getInstance().removeKeypair(string);
    }

    @Override
    public boolean importKeypair(String string, String string1, String string2) {
        return X509Helper.getInstance().importKeypair(string, string1, string2);
    }

    @Override
    public boolean exportKeypair(String string, String string1, String string2) {
        return X509Helper.getInstance().exportKeypair(string, string1, string2);
    }

    @Override
    public boolean signCertificate(String string, String string1) {
        return X509Helper.getInstance().signCertificate(string, string1);
    }

    @Override
    public boolean importCertificate(File file, String string) {
        return X509Helper.getInstance().importCertificate(file, string);
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        return X509Helper.getInstance().exportCertificate(file, i);
    }

    @Override
    public String getIssuer(String string) {
        return X509Helper.getInstance().getIssuer(string);
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String string) {
        return X509Helper.getInstance().getIssuerPublicKeyAlgorithm(string);
    }

    @Override
    public int getRSAKeyLength(String string) {
        return X509Helper.getInstance().getRSAKeyLength(string);
    }

    @Override
    public List<String> getIssuers(String string) {
        return X509Helper.getInstance().getIssuers(string);
    }

    @Override
    public boolean generateCSR(String string) {
        return X509Helper.getInstance().generateCSR(string);
    }
    
}
