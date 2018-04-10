package com.robertsoultanaev.javasphinx;

/**
 * Type used to represent the Sphinx packet as it is encoded into a binary format
 */
public class SphinxPacket {
    public final ParamLengths paramLengths;
    public final HeaderAndDelta headerAndDelta;

    public SphinxPacket(ParamLengths paramLengths, HeaderAndDelta headerAndDelta) {
        this.paramLengths = paramLengths;
        this.headerAndDelta = headerAndDelta;
    }
}
