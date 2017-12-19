import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP224R1Point;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class Group_ECC_Test {

    private Group_ECC group_ecc;

    @Before
    public void setUp() {
        group_ecc = new Group_ECC();
    }

    @Test
    public void expon() throws Exception {
        BigInteger secret = new BigInteger("10242318609670578569309311701916918226942711495988531232197429015905");

        ECPoint base = group_ecc.getGenerator();

        byte[] expectedOutput = Hex.decode("02a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae2");
        byte[] output = group_ecc.expon(base, secret).getEncoded(true);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void multiexpon() throws Exception {
        BigInteger secret1 = new BigInteger("10242318609670578569309311701916918226942711495988531232197429015905");
        BigInteger secret2 = new BigInteger("9166896489953568699130350165214278503117209070949180823539577781184");

        ECPoint base = group_ecc.getGenerator();
        List<BigInteger> exponents = Arrays.asList(secret1, secret2);

        byte[] expectedOutput = Hex.decode("03085f86c52bbb391e7fba0dd1e39541fe89ac5b6afd576c338948abe0");
        byte[] output = group_ecc.multiexpon(base, exponents).getEncoded(true);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void makeexp() throws Exception {
        byte[] data = Hex.decode("03085f86c52bbb391e7fba0dd1e39541fe89ac5b6afd576c338948abe0");

        BigInteger expectedOutput = new BigInteger("881795633944098057513291471553876590759951853908507227127236799785");
        BigInteger output = group_ecc.makeexp(data);

        assertEquals(expectedOutput, output);
    }

    @Test
    public void printable() throws Exception {
        byte[] encodedEcPoint = Hex.decode("02a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae2");
        ECCurve ecCurve = ECNamedCurveTable.getParameterSpec("secp224r1").getCurve();
        ECPoint ecPoint = ecCurve.decodePoint(encodedEcPoint);

        byte[] expectedOutput = Hex.decode("04a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae21a0a05d040ade5db0d89c90a9ec1970c7642bcaa5bc9319ceee935d0");
        byte[] output = group_ecc.printable(ecPoint);

        assertArrayEquals(expectedOutput, output);
    }
}