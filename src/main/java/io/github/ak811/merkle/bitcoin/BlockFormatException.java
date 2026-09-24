package io.github.ak811.merkle.bitcoin;

/** Thrown when bytes do not form a well-formed Bitcoin block or transaction. */
public class BlockFormatException extends Exception {

    private static final long serialVersionUID = 1L;

    public BlockFormatException(String message) {
        super(message);
    }
}
