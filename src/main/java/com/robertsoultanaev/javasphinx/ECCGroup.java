package com.robertsoultanaev.javasphinx;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

public class ECCGroup {
    public static String DEFAULT_CURVE_NAME = "secp224r1";
    public static int DEFAULT_CURVE_NID = 713;

    private final ECPoint generator;
    private final BigInteger order;

    public ECCGroup() {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(DEFAULT_CURVE_NAME);
        generator = ecSpec.getG();
        order = ecSpec.getN();
    }

    public BigInteger genSecret() {
        SecureRandom secureRandom = new SecureRandom();
        BigInteger lowerBound = BigInteger.ZERO;
        BigInteger upperBound = order.subtract(BigInteger.ONE);
        return BigIntegers.createRandomInRange(lowerBound, upperBound, secureRandom);
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
        // Treat data as an unsigned value
        BigInteger bigIntFromData = new BigInteger(1, data);

        return bigIntFromData.mod(this.order);
    }

    public byte[] printable(ECPoint alpha) {
        return alpha.getEncoded(false);
    }

}
