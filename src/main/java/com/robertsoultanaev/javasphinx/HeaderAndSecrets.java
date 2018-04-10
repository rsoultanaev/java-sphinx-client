package com.robertsoultanaev.javasphinx;

/**
 * Type to combine Sphinx header and secrets used to encrypt the Sphinx payload
 */
public class HeaderAndSecrets {
    public final Header header;
    public final byte[][] secrets;

    public HeaderAndSecrets(Header header, byte[][] secrets) {
        this.header = header;
        this.secrets = secrets;
    }
}
