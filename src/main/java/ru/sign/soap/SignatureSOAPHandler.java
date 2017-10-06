package ru.sign.soap;

import org.apache.xml.security.c14n.Canonicalizer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.Set;

import static ru.sign.soap.CryptoHelper.*;
import static ru.sign.soap.PreparedHeader.prepared;


public class SignatureSOAPHandler implements SOAPHandler<SOAPMessageContext> {
    private KeyStore KEYSTORE;
    private PrivateKey PRIVATE_KEY;
    private String ALIAS;

    static {
        Security.addProvider(new BouncyCastleProvider());
        org.apache.xml.security.Init.init();
    }

    /**
     * Конструктор - создание SignatureSOAPHandler с определенными значениями
     *
     * @param ks       KeyStore
     * @param alias    alias для подписи Signature
     * @param password пароль для alias
     * @throws RuntimeException не валидный KeyStore (UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException)
     */
    public SignatureSOAPHandler(KeyStore ks, String alias, String password) {
        this.KEYSTORE = ks;
        this.ALIAS = alias;
        try {
            this.PRIVATE_KEY = (PrivateKey) KEYSTORE.getKey(alias, password.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Конструктор - создание SignatureSOAPHandler с заполнением значений из signatureSOAP.properties
     *
     * @throws RuntimeException
     */
    public SignatureSOAPHandler() {
        Properties prop = getKeyStoreProperties();

        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(this.getClass().getClassLoader().getResourceAsStream("keystore"), prop.getProperty("sign.soap.key.store.password").toCharArray());
            this.KEYSTORE = ks;

            this.ALIAS = prop.getProperty("sign.soap.key.store.region.alias.name");
            this.PRIVATE_KEY = (PrivateKey) KEYSTORE.getKey(ALIAS, prop.getProperty("sign.soap.key.store.region.alias.password").toCharArray());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean handleMessage(SOAPMessageContext context) {

        try {
            Boolean isOutbound = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
            SOAPMessage message = context.getMessage();
            try {
                if (message.getSOAPHeader() == null) {
                    message.getSOAPPart().getEnvelope().addHeader();
                }
            } catch (SOAPException e) {
                throw new RuntimeException("SOAPHandler.header.error", e);
            }

            try {
                if (isOutbound != null && isOutbound) {
                    prepared(message);

                    X509Certificate cert = (X509Certificate) KEYSTORE.getCertificate(ALIAS);
                    ((SOAPElement) com.sun.org.apache.xpath.internal.XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='BinarySecurityToken']"))
                            .addTextNode(getPEMString(cert));

                    ((SOAPElement) com.sun.org.apache.xpath.internal.XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='DigestValue']"))
                            .addTextNode(
                                    getBase64Digest(
                                            new String(
                                                    Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                                                            .canonicalizeSubtree(message.getSOAPBody()), "UTF-8")));

                    ((SOAPElement) com.sun.org.apache.xpath.internal.XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='SignatureValue']"))
                            .addTextNode(
                                    getSignature(
                                            new String(
                                                    Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                                                            .canonicalizeSubtree(
                                                                    com.sun.org.apache.xpath.internal.XPathAPI.selectSingleNode(message.getSOAPHeader(),
                                                                            "//*[local-name()='SignedInfo']"))), PRIVATE_KEY));
                } else {
                    if (!valid(message)) {
                        return false;
                    }
                }

            } catch (NullPointerException e) {
                throw new RuntimeException("SOAPHandler.envelope.error", e.fillInStackTrace());
            }

            return true;
        } catch (Exception e) {
            throw new RuntimeException("SOAPHandler.envelope.error", e);
        }
    }

    protected boolean valid(SOAPMessage message) throws SOAPException, TransformerException, KeyStoreException {
        SecurityVerifier verifier = new SecurityVerifier();
        //X509Certificate cert = (X509Certificate)KEYSTORE.getCertificate(com.sun.org.apache.xpath.internal.XPathAPI.selectSingleNode(message.getSOAPBody(), "//*[local-name()='Sender']").getTextContent());
        return verifier.check(message, null);
    }

    @Override
    public boolean handleFault(SOAPMessageContext context) {
        return false;
    }

    @Override
    public void close(MessageContext context) {

    }

    @Override
    public Set<QName> getHeaders() {
        return null;
    }

    private Properties getKeyStoreProperties() {
        Properties prop = new Properties();
        InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("placeholders.properties");
        if (inputStream != null) {
            try {
                prop.load(inputStream);
            } catch (IOException e) {
                throw new RuntimeException("KeyStoreProperties load error", e);
            }
            return prop;
        } else {
            throw new RuntimeException("KeyStoreProperties not found");
        }
    }
}