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

        if (beta.length != (params.getHeaderLength() - 32)) {
            throw new SphinxException("Length of beta (" + beta.length + ") did not match expected length (" + (params.getHeaderLength() - 32) + ")");
        }

        if (!Arrays.equals(gamma, params.mu(params.hmu(aesS), beta))) {
            throw new SphinxException("MAC mismatch");
        }

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

        Header header = new Header(alpha, beta, gamma);

        HeaderAndDelta headerAndDelta1 = new HeaderAndDelta(header, delta);

        ProcessedPacket ret = new ProcessedPacket(tag, routing, headerAndDelta1);

        return ret;
    }
}
