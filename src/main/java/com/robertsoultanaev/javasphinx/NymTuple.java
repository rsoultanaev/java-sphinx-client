package com.robertsoultanaev.javasphinx;

/**
 * Class to represent the reply block used for replying to anonymous recipients
 */
public class NymTuple {
    public final byte[] node;
    public final Header header;
    public final byte[] ktilde;

    public NymTuple(byte[] node, Header header, byte[] ktilde) {
        this.node = node;
        this.header = header;
        this.ktilde = ktilde;
    }
}
