package ist.cert.example.java;

import org.json.JSONArray;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class CertVerify {
    public List<String> getHashesFromLocal(String aURL) throws Exception {
        URL destinationURL = new URL(aURL);
        HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
        conn.connect();
        Certificate[] certs = conn.getServerCertificates();
        return Arrays.asList(Arrays.stream(certs).map(
                certificate -> {
                    try {
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        md.update(certificate.getEncoded());
                        return DatatypeConverter.printHexBinary(md.digest()).toLowerCase();
                    } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                    return null;
                }
        ).toArray(String[]::new));
    }

    public ArrayList<String> getHashesFromApi(String url) {
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
                JSONObject jsonObject = new JSONObject(sb.toString());
                JSONArray chain = jsonObject.getJSONArray("chain");
                ArrayList<String> resp = new ArrayList<>(chain.length());
                for (int i = 0; i < chain.length(); i++) {
                    resp.add(((JSONObject) chain.get(i))
                            .getJSONObject("der")
                            .getJSONObject("hashes")
                            .getString("sha256"));
                }
                return resp;
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

    public static void main(String[] args) throws Exception {
        CertVerify certVerify = new CertVerify();
        String domain = "urip.io";
        List<String> remoteSha256 = certVerify.getHashesFromApi(String.format("https://api.cert.ist/%s", domain));
        List<String> localSha256 = certVerify.getHashesFromLocal(String.format("https://%s", domain));
        System.out.printf("Certificate chain hashes via cert.ist api: %s\n", remoteSha256);
        System.out.printf("Certificate chain hashes via local Java:   %s\n", localSha256);
        System.out.printf("Do certificate fingerprints match? %s\n", localSha256.equals(remoteSha256));
    }
}
