package com.robertsoultanaev.javasphinx;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Class to house various utility methods.
 */
public class Util {
    /**
     * Concatenate the provided byte arrays into one byte array.
     * @param arrays Array of byte arrays.
     * @return Byte array resulted from concatenating the inputs.
     */
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

    /**
     * Decode an elliptic curve point from its binary representation.
     * @param encodedECPoint Binary representation of an elliptic curve point.
     * @return Elliptic curve point as the ECPoint type.
     */
    public static ECPoint decodeECPoint(byte[] encodedECPoint) {
        ECCurve ecCurve = ECNamedCurveTable.getParameterSpec(ECCGroup.DEFAULT_CURVE_NAME).getCurve();
        return ecCurve.decodePoint(encodedECPoint);
    }

    /**
     * Create a contiguous subarray from the index start to the index (end - 1) of the source array. Operates like Python's slicing syntax.
     * @param source Source array.
     * @param start Starting index.
     * @param end Ending index + 1;
     * @return Contiguous subarray from the index start to the index (end - 1) of the source array.
     */
    public static byte[] slice(byte[] source, int start, int end) {
        int resultLength = end - start;
        byte[] result = new byte[resultLength];
        System.arraycopy(source, start, result, 0, resultLength);
        return result;
    }

    /**
     * Create a contiguous subarray from the index 0 to the index (end - 1) of the source array. Operates like Python's slicing syntax.
     * @param source Source array.
     * @param end Starting index.
     * @return Contiguous subarray from the index 0 to the index (end - 1) of the source array.
     */
    public static byte[] slice(byte[] source, int end) {
        return slice(source, 0, end);
    }
}
