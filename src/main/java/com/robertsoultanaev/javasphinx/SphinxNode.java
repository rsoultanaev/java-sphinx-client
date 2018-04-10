package com.robertsoultanaev.javasphinx;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

import static com.robertsoultanaev.javasphinx.Util.slice;
import static com.robertsoultanaev.javasphinx.Util.concatenate;

/**
 * Class to house the methods used by mix nodes to process Sphinx packets
 */
public class SphinxNode {
    /**
     * Method that processes Sphinx packets at a mix node
     * @param params Sphinx parameters
     * @param secret Mix node's private key
     * @param headerAndDelta Header and encrypted payload of the Sphinx packet
     * @return The new header and payload of the Sphinx packet along with some auxiliary information
     */
    public static ProcessedPacket sphinxProcess(SphinxParams params, BigInteger secret, HeaderAndDelta headerAndDelta) {
        ECCGroup group = params.getGroup();
        ECPoint alpha = headerAndDelta.header.alpha;
        byte[] beta = headerAndDelta.header.beta;
        byte[] gamma = headerAndDelta.header.gamma;
        byte[] delta = headerAndDelta.delta;

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
        byte[] betaPad = concatenate(beta, betaPadZeroes);

        byte[] B = params.xorRho(params.hrho(aesS), betaPad);

        byte length = B[0];
        byte[] routing = slice(B, 1, 1 + length);
        byte[] rest = slice(B, 1 + length, B.length);

        byte[] tag = params.htau(aesS);
        BigInteger b = params.hb(alpha, aesS);
        alpha = group.expon(alpha, b);
        gamma = slice(rest, params.getKeyLength());
        beta = slice(rest, params.getKeyLength(), params.getKeyLength() + (params.getHeaderLength() - 32));
        delta = params.pii(params.hpi(aesS), delta);

        byte[] macKey = params.hpi(aesS);

        Header header = new Header(alpha, beta, gamma);

        HeaderAndDelta headerAndDelta1 = new HeaderAndDelta(header, delta);

        ProcessedPacket ret = new ProcessedPacket(tag, routing, headerAndDelta1, macKey);

        return ret;
    }
}
