package com.robertsoultanaev.javasphinx;

public class SphinxPacket {
    public final ParamLengths paramLengths;
    public final HeaderAndDelta headerAndDelta;

    public SphinxPacket(ParamLengths paramLengths, HeaderAndDelta headerAndDelta) {
        this.paramLengths = paramLengths;
        this.headerAndDelta = headerAndDelta;
    }
}
