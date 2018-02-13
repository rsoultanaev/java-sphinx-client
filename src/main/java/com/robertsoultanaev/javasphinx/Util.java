package com.robertsoultanaev.javasphinx;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class Util {
    public static byte[] concatenate(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }

        byte[] result = new byte[length];

        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }

        return result;
    }

    public static ECPoint decodeECPoint(byte[] encodedECPoint) {
        ECCurve ecCurve = ECNamedCurveTable.getParameterSpec(ECCGroup.DEFAULT_CURVE_NAME).getCurve();
        return ecCurve.decodePoint(encodedECPoint);
    }

    public static byte[] slice(byte[] source, int start, int end) {
        int resultLength = end - start;
        byte[] result = new byte[resultLength];
        System.arraycopy(source, start, result, 0, resultLength);
        return result;
    }

    public static byte[] slice(byte[] source, int end) {
        return slice(source, 0, end);
    }
}
