import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import java.math.BigInteger;
import java.util.List;

public class Group_ECC {
    private final ECPoint generator;
    private final BigInteger order;

    public Group_ECC() {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp224r1");
        generator = ecSpec.getG();
        order = ecSpec.getN();
    }

    public ECPoint getGenerator() {
        return generator;
    }

    public BigInteger getOrder() {
        return order;
    }

    public ECPoint expon(ECPoint base, BigInteger exp) {
        return base.multiply(exp);
    }

    public ECPoint multiexpon(ECPoint base, List<BigInteger> exponents) {
        BigInteger finalExponent = new BigInteger("1");
        for (BigInteger exponent : exponents) {
            finalExponent = finalExponent.multiply(exponent).mod(order);
        }

        return base.multiply(finalExponent);
    }

    public BigInteger makeexp(byte[] data) {
        BigInteger bigIntFromData = new BigInteger(data);

        return bigIntFromData.mod(this.order);
    }

    public byte[] printable(ECPoint alpha) {
        return alpha.getEncoded(false);
    }

}
