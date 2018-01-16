package com.robertsoultanaev.javasphinx;

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
