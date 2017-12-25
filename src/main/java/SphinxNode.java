import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

public class SphinxNode {
    public static ProcessedPacket sphinxProcess(SphinxParams params, BigInteger secret, HeaderAndDelta headerAndDelta) {
        ECCGroup group = params.getGroup();
        ECPoint alpha = headerAndDelta.header.alpha;
        byte[] beta = headerAndDelta.header.beta;
        byte[] gamma = headerAndDelta.header.gamma;
        byte[] delta = headerAndDelta.delta;

        // TODO: check that alpha is in the group used by params

        ECPoint s = group.expon(alpha, secret);
        byte[] aesS = params.getAesKey(s);

        assert(beta.length == (params.getHeaderLength() - 32));
        assert(Arrays.equals(gamma, params.mu(params.hmu(aesS), beta)));

        byte[] betaPadZeroes = new byte[2 * params.getBodyLength()];
        Arrays.fill(betaPadZeroes, (byte) 0x00);
        byte[] betaPad = Util.concatByteArrays(beta, betaPadZeroes);

        byte[] B = params.xorRho(params.hrho(aesS), betaPad);

        byte length = B[0];
        byte[] routing = Arrays.copyOfRange(B, 1, 1 + length);
        byte[] rest = Arrays.copyOfRange(B, 1 + length, B.length);

        byte[] tag = params.htau(aesS);
        BigInteger b = params.hb(alpha, aesS);
        alpha = group.expon(alpha, b);
        gamma = Arrays.copyOf(rest, params.getKeyLength());
        beta = Arrays.copyOfRange(rest, params.getKeyLength(), params.getKeyLength() + (params.getHeaderLength() - 32));
        delta = params.pii(params.hpi(aesS), delta);

        Header header = new Header();
        header.alpha = alpha;
        header.beta = beta;
        header.gamma = gamma;

        HeaderAndDelta headerAndDelta1 = new HeaderAndDelta();
        headerAndDelta1.header = header;
        headerAndDelta1.delta = delta;

        ProcessedPacket ret = new ProcessedPacket();
        ret.tag = tag;
        ret.routing = routing;
        ret.headerAndDelta = headerAndDelta1;

        return ret;
    }
}
