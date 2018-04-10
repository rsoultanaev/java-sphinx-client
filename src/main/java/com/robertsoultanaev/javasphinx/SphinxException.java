package com.robertsoultanaev.javasphinx;

/**
 * Custom RuntimeException type raised during irrecoverable issues
 */
public class SphinxException extends RuntimeException {
    public SphinxException(String message) {
        super(message);
    }
}