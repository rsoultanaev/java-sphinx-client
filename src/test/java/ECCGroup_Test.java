import com.robertsoultanaev.javasphinx.ECCGroup;
import com.robertsoultanaev.javasphinx.Util;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class ECCGroup_Test {

    private ECCGroup eccGroup;

    @Before
    public void setUp() {
        eccGroup = new ECCGroup();
    }

    @Test
    public void expon() throws Exception {
        BigInteger secret = new BigInteger("10242318609670578569309311701916918226942711495988531232197429015905");

        ECPoint base = eccGroup.getGenerator();

        byte[] expectedOutput = Hex.decode("02a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae2");
        byte[] output = eccGroup.expon(base, secret).getEncoded(true);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void multiexpon() throws Exception {
        BigInteger secret1 = new BigInteger("10242318609670578569309311701916918226942711495988531232197429015905");
        BigInteger secret2 = new BigInteger("9166896489953568699130350165214278503117209070949180823539577781184");

        ECPoint base = eccGroup.getGenerator();
        List<BigInteger> exponents = Arrays.asList(secret1, secret2);

        byte[] expectedOutput = Hex.decode("03085f86c52bbb391e7fba0dd1e39541fe89ac5b6afd576c338948abe0");
        byte[] output = eccGroup.multiexpon(base, exponents).getEncoded(true);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void makeexp() throws Exception {
        byte[] data1 = Hex.decode("03085f86c52bbb391e7fba0dd1e39541fe89ac5b6afd576c338948abe0");
        byte[] data2 = Hex.decode("e53c7751c276d49da8a6dacbfd1b9a0b");

        BigInteger expectedOutput1 = new BigInteger("881795633944098057513291471553876590759951853908507227127236799785");
        BigInteger expectedOutput2 = new BigInteger("304707168930665571958916740110488410635");

        BigInteger output1 = eccGroup.makeexp(data1);
        BigInteger output2 = eccGroup.makeexp(data2);

        assertEquals(expectedOutput1, output1);
        assertEquals(expectedOutput2, output2);
    }

    @Test
    public void printable() throws Exception {
        byte[] encodedEcPoint = Hex.decode("02a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae2");
        ECPoint ecPoint = Util.decodeECPoint(encodedEcPoint);

        byte[] expectedOutput = Hex.decode("04a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae21a0a05d040ade5db0d89c90a9ec1970c7642bcaa5bc9319ceee935d0");
        byte[] output = eccGroup.printable(ecPoint);

        assertArrayEquals(expectedOutput, output);
    }
}