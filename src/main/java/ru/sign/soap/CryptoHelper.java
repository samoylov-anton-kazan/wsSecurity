package ru.sign.soap;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;

public class CryptoHelper {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Формирует хэш данных кодирует его в base64
     *
     * @param data входные данные
     * @return хэш в base64
     */
    public static String getBase64Digest(String data) {
        Digest digest = new SHA1Digest();
        digest.update(data.getBytes(), 0, data.getBytes().length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        digest.doFinal(resBuf, 0);
        return new String(Base64.encode(resBuf));
    }

    public static String getPEMString(Certificate certificate) {

        StringWriter stringWriter = new StringWriter();
        PEMWriter jcaPEMWriter = new PEMWriter(stringWriter);

        try {
            jcaPEMWriter.writeObject(certificate);
            jcaPEMWriter.flush();
        } catch (IOException ignore) { /*NOP*/ }

        String str = stringWriter.toString()
                .replaceAll("[\n\r]", "")
                .replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .trim();

        return str;
    }

    /**
     * Подписывает данные ЭЦП
     *
     * @param data входные данные
     * @param key  закрытый ключ
     * @return подпись в base64
     * @throws GeneralSecurityException
     */
    public static String getSignature(String data, PrivateKey key) throws GeneralSecurityException {

        Signature signature = Signature.getInstance("SHA256withRSA", "BC");

        signature.initSign(key);
        signature.update(data.getBytes());
        byte[] signBytes = signature.sign();

        return new String(Base64.encode(signBytes));
    }

    /**
     * Проверка подписаннх данных
     *
     * @param sigData подписанные данные
     * @param cer  сертификат для получения открытого ключа
     * @param data проверяемые данные
     * @return verify
     * @throws GeneralSecurityException
     */
    public static Boolean signatureVerify(String sigData, Certificate cer, String data) throws GeneralSecurityException {

        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initVerify(cer.getPublicKey());
        signature.update(data.getBytes());

        return signature.verify(Base64.decode(sigData.getBytes()));

    }
}