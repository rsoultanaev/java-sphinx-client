import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class HeaderRecord {
    public final ECPoint alpha;
    public final ECPoint s;
    public final BigInteger b;
    public final byte[] aes;

    public HeaderRecord(ECPoint alpha, ECPoint s, BigInteger b, byte[] aes) {
        this.alpha = alpha;
        this.s = s;
        this.b = b;
        this.aes = aes;
    }
}
