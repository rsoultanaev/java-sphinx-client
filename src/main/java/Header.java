import org.bouncycastle.math.ec.ECPoint;

public class Header {
    public final ECPoint alpha;
    public final byte[] beta;
    public final byte[] gamma;

    public Header(ECPoint alpha, byte[] beta, byte[] gamma) {
        this.alpha = alpha;
        this.beta = beta;
        this.gamma = gamma;
    }
}
