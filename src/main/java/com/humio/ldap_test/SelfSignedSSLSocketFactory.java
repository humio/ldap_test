package com.humio.ldap_test;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class SelfSignedSSLSocketFactory extends SSLSocketFactory {


    static Logger log = Logger.getLogger(SelfSignedSSLSocketFactory.class.getName());

    private static SSLSocketFactory theFactory;
    private static X509Certificate cert;

    public static void setCertificate(String pem_cert1) throws CertificateException {
        String pem_cert = pem_cert1.replaceAll("\\\\n", "\n");

        log.info("Setting LDAP certificate to: \n" + pem_cert );

        InputStream inputStream = new ByteArrayInputStream(pem_cert.getBytes(StandardCharsets.UTF_8));
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate)certificateFactory.generateCertificate(inputStream);
    }

    public static String name() { return SelfSignedSSLSocketFactory.class.getName(); }

    public static synchronized SocketFactory getDefault() {
        if (theFactory == null) {
            try {
                theFactory = createDefault();
            } catch (Exception e) {
                log.log(Level.SEVERE, "failed to create socket", e);
                e.printStackTrace();
            }
        }

        return theFactory;
    }

    private static SSLSocketFactory createDefault() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        return buildSslContext().getSocketFactory();
    }

    public static SSLContext buildSslContext() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null);

        String alias = cert.getSubjectX500Principal().getName();
        trustStore.setCertificateEntry(alias, cert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
        tmf.init(trustStore);
        TrustManager[] trustManagers = tmf.getTrustManagers();
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, null);

        return sslContext;
    }


/*
    private static String test_cert = "-----BEGIN CERTIFICATE-----\\n" +
            "MIIE5DCCAswCCQCWP3L1+ZxNtjANBgkqhkiG9w0BAQsFADA0MQswCQYDVQQGEwJE\\n" +
            "SzEUMBIGA1UECAwLUmVnaW9uIE1pZHQxDzANBgNVBAcMBkFhcmh1czAeFw0xODA4\\n" +
            "MTAxMTExNDJaFw0xOTA4MTAxMTExNDJaMDQxCzAJBgNVBAYTAkRLMRQwEgYDVQQI\\n" +
            "DAtSZWdpb24gTWlkdDEPMA0GA1UEBwwGQWFyaHVzMIICIjANBgkqhkiG9w0BAQEF\\n" +
            "AAOCAg8AMIICCgKCAgEA8mEnTjqzgVdaLrrdHcuv6NuYp7orzvyPnPGkmG2hKMTi\\n" +
            "w/uL3I3BnX+prnKPtz57ErSmOChitpiHQAvZUjhfkQLuhyC9dpOZzUNgugKLiRrV\\n" +
            "C1KckufwIi6wQmE/0sZQQEW/vlc77DTn2v8O2nLCHBrh691iUhc8S9lQWhpYeRfC\\n" +
            "M0exEXTM/Qq3dTzggY1d95Vr7TRVYjj/wDkUK0S08pnsJiHzd0RPxlYXlf89he/y\\n" +
            "Xt41eHainlFr49AFizOjm3Df6Wnv8DkLvwQDlp1sUCm1cQ581fP+beCcZTzggGHN\\n" +
            "Wk/nXRTvW3Z8Vd/4X59O/EkecdOrVo/tDUixhXNpwFtMLV/2YaYgyu5Ohnp8FFiH\\n" +
            "bF+htIbWV5bCYgzML9GRDo5uu/ZgKOpOSxz19rNeDlCX543fcaPIzUyN90iKehwP\\n" +
            "XfZwNfXIezwDGU444Eew5OYLdGBg3qa+JPORsTmdlrSOJ70FDAlyYGT+qe64eD80\\n" +
            "JLaoXY6+JXyegvNN6Uh6DWy6iA/YIsxEZtlsvTH5g4oLEYVAvHrnMJpEkniTWp+M\\n" +
            "e8P/FgmSyb4wq56f4bo75KUswjJ+OvEDrs9nhzm8tGKf8NKrmMz/kjWZq/UyEvHR\\n" +
            "7xNTyjmuJZevPEHR6ZbmeRAj3OVh5uphnhXDwIXaVcAEzYoELpPIf+PYQfGBCVkC\\n" +
            "AwEAATANBgkqhkiG9w0BAQsFAAOCAgEAbk71t7YSQYRM5+ORO/4z+3US2SsnYrUn\\n" +
            "0YbOOsR2ox8WcNIFF3eL5fY/PVYSXvJjrZmHfh8QS2C6jiTkS0PYzOUq5MEKLvpy\\n" +
            "DWSSnltaAkpwrWQ7pSNWFsRP/J2y0Oe5knd4rIwK9DmZtSUPzvBruXhN8ikQ0tE3\\n" +
            "hMsAp0UzAZlPsQcrKQ9acV5OHX3LGwt6ZOSU+KfdR11cn6Pb+YcZqOS4leL+lrw3\\n" +
            "fJgHJ732tprPSLZmisMVo6XsMcFduHdvF03xewZtYAQ+A+SnXdbW+E+GFVptroAg\\n" +
            "9mGwOqOPJ0SrIO30AWTY9i8QJ7MXSF+AWJj4X1DPrr2cTjUPO3l1cvmqpz13YZMB\\n" +
            "Mww6Xuh5uUI8eEsHHwY8O5eJPA2xl3RQb5JVoffGzLej0AqVLEC+XylNyfbs+a08\\n" +
            "ztQzFUjWfhrmf5jc+coqXAHffEOxYWvhBMafpZKvppVQXdzQP2+a/eTwIVueNnaN\\n" +
            "xIejUKljWWV/DcS6g7Jyq6c0ne9G0ecgVp742s5EvgGt7Pl6tx7aS2PSc09fEiYy\\n" +
            "GHdI5AhSzjmexNDUdhlo4JgAIpUj3MS6YJyHdIdYCaV0sSWeZohzTdsV8ZHG6Eke\\n" +
            "KWhSrp6pGPhpuyBgjQ87hQM15bw1iCZaZ8m6TDpciZb+TCBVmztLmd9zY9gNpkKs\\n" +
            "xNd/XVOLgWc=\\n" +
            "-----END CERTIFICATE-----\\n";


    public static void main(String[] args) throws CertificateException, IOException {
        setCertificate(test_cert);

        Socket sock = getDefault().createSocket("localhost", 4433);

        OutputStream o = sock.getOutputStream();
        o.write("hello world\n".getBytes());
        o.flush();
        sock.close();
    }

*/

}
