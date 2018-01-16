package com.robertsoultanaev.javasphinx;

public class ProcessedPacket {
    public final byte[] tag;
    public final byte[] routing;
    public final HeaderAndDelta headerAndDelta;

    public ProcessedPacket(byte[] tag, byte[] routing, HeaderAndDelta headerAndDelta) {
        this.tag = tag;
        this.routing = routing;
        this.headerAndDelta = headerAndDelta;
    }
}
