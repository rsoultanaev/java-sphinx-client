import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class HeaderRecord {
    public ECPoint alpha;
    public ECPoint s;
    public BigInteger b;
    public byte[] aes;
}
