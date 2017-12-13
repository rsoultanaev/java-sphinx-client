import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.Assert.*;

public class SphinxParams_Test {

    private SphinxParams params;
    private byte[] key;
    private byte[] plaintext;

    @Before
    public void setUp() throws Exception {
        params = new SphinxParams();
        key = Hex.decode("5f060d3716b345c253f6749abac10917");
        plaintext = Hex.decode("265f3338efbf92c9feacf25fb10778b6d96996e72b41c4e4f55f373d182ba4e1acd5b972e95a917da9f6946924aab6e0b926b94996c25bea7e00422d1f11468578b60f460cb5ce2eafa72fef8cb1a2de");
    }

    @Test
    public void aesCtrEncrypt() throws Exception {
        byte[] iv = Hex.decode("18e3e4c93f5bdd1fb4961630309206e6");

        byte[] expectedOutput = Hex.decode("fbf3df496e16a07c149c197a1772e9901a7fbac16a9424c6282ed06624e4fdec5b2c1c50a347fb782647c8bce5b9a04b32a3eaa1c2d2aae082aad017103aa212e32569a45f0436ff4a5ea95c52522c92");
        byte[] output = params.aesCtr(key, plaintext, iv);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void aesCtrEncryptNoIV() throws Exception {
        byte[] expectedOutput = Hex.decode("0e000098e34558b1c728b1580787f881012f2a1eaf3ac383fd596b13d87a95cce1376225b739b15e630f89fe64dbc54752a22ed567f1b368cae6aa1c374fdb008602fbbe5b1cfe3c7c256669e080903d");
        byte[] output = params.aesCtr(key, plaintext);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void aesCtrEncryptThenDecrypt() throws Exception {
        byte[] iv = Hex.decode("18e3e4c93f5bdd1fb4961630309206e6");

        byte[] ciphertext = params.aesCtr(key, plaintext, iv);
        byte[] decryptedCiphertext = params.aesCtr(key, ciphertext, iv);

        assertArrayEquals(plaintext, decryptedCiphertext);
    }

    @Test
    public void lionessEncrypt() throws Exception {
        byte[] expectedOutput = Hex.decode("937e52902f5300c07b0dbd39d4e10b9d0de98278ed16d2ef2f4652d5318041da6d16188c11f4dbfba12b36f7e23a1a8daebff5942703463241d7ed2c909116e913bb9f74d645fb8d99971f299d21ac51");
        byte[] output = params.lionessEnc(key, plaintext);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void lionessEncryptThenDecrypt() throws Exception {
        byte[] ciphertext = params.lionessEnc(key, plaintext);
        byte[] decryptedCiphertext = params.lionessDec(key, ciphertext);

        assertArrayEquals(plaintext, decryptedCiphertext);
    }

    @Test
    public void xorRho() throws Exception {
        byte[] expectedOutput = Hex.decode("0e000098e34558b1c728b1580787f881012f2a1eaf3ac383fd596b13d87a95cce1376225b739b15e630f89fe64dbc54752a22ed567f1b368cae6aa1c374fdb008602fbbe5b1cfe3c7c256669e080903d");
        byte[] output = params.xorRho(key, plaintext);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void mu() throws Exception {
        byte[] expectedOutput = Hex.decode("90993216df7f52e7a2ea9db410a462fd");
        byte[] output = params.mu(key, plaintext);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void piEncryptThenDecrypt() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] plaintext = new byte[1024];
        random.nextBytes(plaintext);

        byte[] ciphertext = params.pi(key, plaintext);
        byte[] decryptedCiphertext = params.pii(key, ciphertext);

        assertArrayEquals(plaintext, decryptedCiphertext);
    }

    @Test
    public void hash() throws Exception {
        byte[] expectedOutput = Hex.decode("75cab8f34fc4fed6ad3dd420b1f558a9c55549496316ded97f6bdbf6c5b201e1");
        byte[] output = params.hash(plaintext);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void getAesKey() throws Exception {
        byte[] encodedEcPoint = Hex.decode("02a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae2");
        ECCurve ecCurve = ECNamedCurveTable.getParameterSpec("secp224r1").getCurve();
        ECPoint s = ecCurve.decodePoint(encodedEcPoint);

        byte[] expectedOutput = Hex.decode("ef9706c84715d56800ef8fceb5671d55");
        byte[] output = params.getAesKey(s);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void deriveKey() throws Exception {
        byte[] flavor = "aaaaaaaaaaaaaaaa".getBytes(StandardCharsets.US_ASCII);

        byte[] expectedOutput = Hex.decode("89d2eb817c3a90755cc952254323c342");
        byte[] output = params.deriveKey(key, flavor);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void hb() throws Exception {
        byte[] encodedEcPoint = Hex.decode("02a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae2");
        ECCurve ecCurve = ECNamedCurveTable.getParameterSpec("secp224r1").getCurve();
        ECPoint alpha = ecCurve.decodePoint(encodedEcPoint);

        BigInteger expectedOutput = new BigInteger("99291632524521846780855783327754112432");
        BigInteger output = params.hb(alpha, key);

        assertEquals(expectedOutput, output);
    }

    @Test
    public void hrho() throws Exception {
        byte[] expectedOutput = Hex.decode("a941fceaec8077174e46e0c1e40dc454");
        byte[] output = params.hrho(key);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void hmu() throws Exception {
        byte[] expectedOutput = Hex.decode("be430289b8937b4ded6bf31f6e8ac891");
        byte[] output = params.hmu(key);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void hpi() throws Exception {
        byte[] expectedOutput = Hex.decode("f74e9cf22a397c70c033cf47f2e63523");
        byte[] output = params.hpi(key);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void htau() throws Exception {
        byte[] expectedOutput = Hex.decode("5d6904bdc9c4fb34e30d8d807b130d82");
        byte[] output = params.htau(key);

        assertArrayEquals(expectedOutput, output);
    }

}
