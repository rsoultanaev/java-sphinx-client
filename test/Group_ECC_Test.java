import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class Group_ECC_Test {

    private BigInteger secret1;
    private BigInteger secret2;
    private BigInteger secret3;

    private Group_ECC group_ecc;

    private String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789abcdef".toCharArray();

        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    @Before
    public void setUp() {
        secret1 = new BigInteger("10242318609670578569309311701916918226942711495988531232197429015905");
        secret2 = new BigInteger("9166896489953568699130350165214278503117209070949180823539577781184");
        secret3 = new BigInteger("7306929579332400726108483579260842691270825133579789121406740491622");

        group_ecc = new Group_ECC();
    }

    @Test
    public void expon() throws Exception {
        String expectedOutput1 = "02a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae2";
        String expectedOutput2 = "0211a8818e3e4c93f5bdd1fb4961630309206e61a9653d4f5bd0821455";
        String expectedOutput3 = "02686c1f9d7fce854cdf51046948bec184fed66dd49554f0ce856d6f21";

        ECPoint base = group_ecc.getGenerator();

        String output1 = bytesToHex(group_ecc.expon(base, secret1).getEncoded(true));
        String output2 = bytesToHex(group_ecc.expon(base, secret2).getEncoded(true));
        String output3 = bytesToHex(group_ecc.expon(base, secret3).getEncoded(true));

        assertEquals(expectedOutput1, output1);
        assertEquals(expectedOutput2, output2);
        assertEquals(expectedOutput3, output3);
    }

    @Test
    public void multiexpon() throws Exception {
        String expectedOutput1 = "03085f86c52bbb391e7fba0dd1e39541fe89ac5b6afd576c338948abe0";
        String expectedOutput2 = "02bb81557527fe5b00c896006836276f5de1041681c8714060e25995fe";
        String expectedOutput3 = "03bba85f69eb9ab0a8a0b9b4b0e9c84aba412b36083d8c6f10c13a58ce";

        List<BigInteger> exponents1 = Arrays.asList(secret1, secret2);
        List<BigInteger> exponents2 = Arrays.asList(secret1, secret3);
        List<BigInteger> exponents3 = Arrays.asList(secret2, secret3);

        ECPoint base = group_ecc.getGenerator();

        String output1 = bytesToHex(group_ecc.multiexpon(base, exponents1).getEncoded(true));
        String output2 = bytesToHex(group_ecc.multiexpon(base, exponents2).getEncoded(true));
        String output3 = bytesToHex(group_ecc.multiexpon(base, exponents3).getEncoded(true));

        assertEquals(expectedOutput1, output1);
        assertEquals(expectedOutput2, output2);
        assertEquals(expectedOutput3, output3);
    }

}