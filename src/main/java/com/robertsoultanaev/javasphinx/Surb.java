package com.robertsoultanaev.javasphinx;

/**
 * Type to combine a reply block and the related information
 */
public class Surb {
    public final byte[] xid;
    public final byte[][] keytuple;
    public final NymTuple nymTuple;

    public Surb(byte[] xid, byte[][] keytuple, NymTuple nymTuple) {
        this.xid = xid;
        this.keytuple = keytuple;
        this.nymTuple = nymTuple;
    }
}
