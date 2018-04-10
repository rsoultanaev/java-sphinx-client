package com.robertsoultanaev.javasphinx;

/**
 * Type to combine destination and message
 */
public class DestinationAndMessage {
    public final byte[] destination;
    public final byte[] message;

    public DestinationAndMessage(byte[] destination, byte[] message) {
        this.destination = destination;
        this.message = message;
    }
}
