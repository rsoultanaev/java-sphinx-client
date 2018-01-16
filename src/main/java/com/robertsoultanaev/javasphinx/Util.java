package com.robertsoultanaev.javasphinx;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class Util {
    public static byte[] concatByteArrays(byte[]... arrays) {
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
}
