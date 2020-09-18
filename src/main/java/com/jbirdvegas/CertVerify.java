package com.jbirdvegas;

import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import javax.xml.bind.DatatypeConverter;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

public class CertVerify {
    public String certInformation(String aURL) throws Exception {
        URL destinationURL = new URL(aURL);
        HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
        conn.connect();
        Certificate[] certs = conn.getServerCertificates();
        Optional<Certificate> first = Arrays.stream(certs).findFirst();
        if (first.isPresent()) {
            Certificate cert = first.get();
            if (cert instanceof X509Certificate) {
                X509Certificate x = (X509Certificate) cert;
                return getThumbprint(x);
            }
        }
        return aURL;
    }

    public String getJsonFromUrl(String url) {
        HttpsURLConnection con = null;
        try {
            URL u = new URL(url);
            con = (HttpsURLConnection) u.openConnection();
            con.connect();
            try (InputStreamReader isr = new InputStreamReader(con.getInputStream());
                 BufferedReader br = new BufferedReader(isr)) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                return extractShaHash(sb.toString());
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            if (con != null) {
                try {
                    con.disconnect();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        }
        return null;
    }

    private static String getThumbprint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        String digestHex = DatatypeConverter.printHexBinary(digest);
        return digestHex.toLowerCase();
    }

    private String extractShaHash(String json) {
        JSONObject jsonObject = new JSONObject(json);
        JSONObject certificate = (JSONObject) jsonObject.get("certificate");
        JSONObject hashes = (JSONObject) certificate.get("hashes");
        return hashes.getString("sha256");
    }

    public static void main(String[] args) throws Exception {
        CertVerify certVerify = new CertVerify();
        String domain = "urip.io";
        String remoteSha256 = certVerify.getJsonFromUrl(String.format("https://api.cert.ist/%s", domain));
        String localSha256 = certVerify.certInformation(String.format("https://%s", domain));
        System.out.printf("Certificate hash via cert.ist api: %s%n", remoteSha256);
        System.out.printf("Certificate hash via local Java:   %s%n", localSha256);
        System.out.printf("Do certificate fingerprints match? %s%n", localSha256.equals(remoteSha256));
    }
}
