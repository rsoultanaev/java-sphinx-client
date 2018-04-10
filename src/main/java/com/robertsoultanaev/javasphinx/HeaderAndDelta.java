package com.robertsoultanaev.javasphinx;

/**
 * Type to combine Sphinx header and payload
 */
public class HeaderAndDelta {
    public final Header header;
    public final byte[] delta;

    public HeaderAndDelta(Header header, byte[] delta) {
        this.header = header;
        this.delta = delta;
    }
}
