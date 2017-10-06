package ru.sign.soap;

/**
 * Created by asamoilov on 03.07.2017.
 */

import com.sun.org.apache.xpath.internal.XPathAPI;
import org.apache.ws.security.message.token.X509Security;
import org.apache.xml.security.c14n.Canonicalizer;

import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPMessage;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class SecurityVerifier {

    /**
     * Проверка security сообщения
     *
     * @param message полученное сообщение
     * @param senderCert сертификат отправителия из KeyStore
     * @throws RuntimeException не валидные данные
     */
    public boolean check(SOAPMessage message, X509Certificate senderCert){

        SOAPElement binarySecurityTokenElement = null;
        try {
            binarySecurityTokenElement = (SOAPElement) XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='BinarySecurityToken']");

        if (binarySecurityTokenElement == null) {
            return false;
        }

        final X509Security x509 = new X509Security(binarySecurityTokenElement);
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(x509.getToken()));

        /*if (senderCert != null && (cert == null || !cert.equals(senderCert))) {
            throw new RuntimeException("certificate to verify error");
        }*/

        String digestValue = com.sun.org.apache.xpath.internal.XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='DigestValue']").getTextContent();
        if (digestValue == null || digestValue.equals(CryptoHelper.getBase64Digest(new String(Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                .canonicalizeSubtree(message.getSOAPBody()), "UTF-8")))) {
            throw new RuntimeException("digestValue not verify");
        }

        SOAPElement signatureValue = (SOAPElement) XPathAPI.selectSingleNode(message.getSOAPHeader(), "//*[local-name()='SignatureValue']");
        String signedInfo = new String(
                Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                        .canonicalizeSubtree(
                                com.sun.org.apache.xpath.internal.XPathAPI.selectSingleNode(message.getSOAPHeader(),
                                        "//*[local-name()='SignedInfo']")));

        return CryptoHelper.signatureVerify(signatureValue.getTextContent(), cert, signedInfo);

        } catch (Exception e) {
            throw new RuntimeException("verify not valid", e);
        }
    }
}
