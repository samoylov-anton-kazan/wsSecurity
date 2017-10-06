package ru.sign.soap;

import javax.xml.namespace.QName;
import javax.xml.soap.*;

/**
 * Created by asamoilov on 30.06.2017.
 */
public class PreparedHeader {

    /**
     * Подготовка сообщения для подписи
     *
     * @param message отправляемое сообщение
     * @throws SOAPException
     */
    public static void prepared(SOAPMessage message) {
        SOAPPart soapPart = message.getSOAPPart();

        try {
            if (message.getSOAPHeader() == null) {
                message.getSOAPPart().getEnvelope().addHeader();
            }

            SOAPEnvelope envelope = soapPart.getEnvelope();
            envelope.addNamespaceDeclaration("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            envelope.addNamespaceDeclaration("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

            SOAPHeader soapHeader = message.getSOAPHeader();

            SOAPBody soapBody = envelope.getBody();
            soapBody.setAttribute("wsu:Id", "TheBody");

            // Добавляем элемент Security в заголовок сообщения и устанавливаем атрибуты
            SOAPHeaderElement security = soapHeader.addHeaderElement(new QName(
                    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security", "wsse"));

            security.addNamespaceDeclaration("ds", "http://www.w3.org/2000/09/xmldsig#");
            security.addNamespaceDeclaration("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            security.addNamespaceDeclaration("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

            security.setActor("http://smev.gosuslugi.ru/actors/smev");

            // Добавляем в Security элемент BinarySecurityToken, устанавливаем атрибуты и идентификатор
            SOAPElement securityToken = security.addChildElement("BinarySecurityToken", "wsse");
            securityToken.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
            securityToken.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
            securityToken.setAttribute("wsu:Id", "x509cert00");

            // Добавляем элемент Signature
            SOAPElement signature = security.addChildElement("Signature", "ds");

            // Добавляем элемент SignedInfo
            SOAPElement signedInfo = signature.addChildElement("SignedInfo", "ds");
            signedInfo.addNamespaceDeclaration("SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/");
            signedInfo.addNamespaceDeclaration("ds", "http://www.w3.org/2000/09/xmldsig#");
            signedInfo.addNamespaceDeclaration("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            signedInfo.addNamespaceDeclaration("xenc", "http://www.w3.org/2001/04/xmlenc#");

            // Добавляем элемент CanonicalizationMethod и указываем алгоритм
            SOAPElement canonicalizationMethod = signedInfo.addChildElement("CanonicalizationMethod", "ds");
            canonicalizationMethod.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
            canonicalizationMethod.addChildElement(new QName(
                    "http://www.w3.org/2001/10/xml-exc-c14n#", "InclusiveNamespaces", "c14n"));

            // Добавляем элемент SignatureMethod и указываем алгоритм
            signedInfo.addChildElement("SignatureMethod", "ds").setAttribute("Algorithm",
                    "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

            // Добавляем элемент Reference
            SOAPElement referenceSignedInfo = signedInfo.addChildElement("Reference", "ds");

            // Добавляем элементы Transforms и Transform, указываем алгоритм
            referenceSignedInfo.addChildElement("Transforms", "ds").addChildElement("Transform", "ds")
                    .setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");

            // Добавляем элемент DigestMethod и указываем алгоритм
            referenceSignedInfo.addChildElement("DigestMethod", "ds").setAttribute("Algorithm",
                    "http://www.w3.org/2000/09/xmldsig#sha1");

            // Добавляем элемент DigestValue (значение хэша считаем позже)
            referenceSignedInfo.addChildElement("DigestValue", "ds");

            // Добавляем ссылку на идентификатор Body
            referenceSignedInfo.setAttribute("URI", "#TheBody");

            // Добавляем элемент SignatureValue (значение ЭЦП считаем позже)
            signature.addChildElement("SignatureValue", "ds");

            // Добавляем элементы для KeyInfo, устанавливаем атрибуты и ссылку на идентификатор сертификата
            SOAPElement referenceKeyInfo = signature.addChildElement("KeyInfo", "ds")
                    .addChildElement("SecurityTokenReference", "wsse")
                    .addChildElement("Reference", "wsse");

            referenceKeyInfo.setAttribute("URI", "#x509cert00");
            referenceKeyInfo.setAttribute("ValueType",
                    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");

        } catch (SOAPException e) {
            e.printStackTrace();
        }

    }
}
