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
        byte[] aes_s = params.getAesKey(s);

        assert(beta.length == (params.getHeaderLength() - 32));
        assert(Arrays.equals(gamma, params.mu(params.hmu(aes_s), beta)));

        byte[] beta_pad_zeroes = new byte[2 * params.getBodyLength()];
        Arrays.fill(beta_pad_zeroes, (byte) 0x00);
        byte[] beta_pad = params.concatByteArrays(beta, beta_pad_zeroes);

        byte[] B = params.xorRho(params.hrho(aes_s), beta_pad);

        byte length = B[0];
        byte[] routing = Arrays.copyOfRange(B, 1, 1 + length);
        byte[] rest = Arrays.copyOfRange(B, 1 + length, B.length);

        byte[] tag = params.htau(aes_s);
        BigInteger b = params.hb(alpha, aes_s);
        alpha = group.expon(alpha, b);
        gamma = Arrays.copyOf(rest, params.getKeyLength());
        beta = Arrays.copyOfRange(rest, params.getKeyLength(), params.getKeyLength() + (params.getHeaderLength() - 32));
        delta = params.pii(params.hpi(aes_s), delta);

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
