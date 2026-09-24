package io.github.ak811.merkle.crypto;

import java.util.Arrays;

/**
 * An immutable 32-byte hash, such as a transaction ID or Merkle root.
 *
 * <p>Bitcoin stores hashes in <b>internal byte order</b> (the raw SHA-256 output) but displays
 * them, in block explorers and RPC output, in <b>display order</b>: the same bytes reversed.
 * This class keeps the internal order and converts explicitly at the boundaries.
 */
public final class Hash32 {

    public static final int SIZE = 32;

    /** The all-zero hash; also the Merkle root of an empty transaction list. */
    public static final Hash32 ZERO = new Hash32(new byte[SIZE]);

    private final byte[] bytes;

    private Hash32(byte[] internalBytes) {
        this.bytes = internalBytes;
    }

    /** Creates a hash from {@code SIZE} bytes in internal order, starting at {@code offset}. */
    public static Hash32 fromInternal(byte[] source, int offset) {
        if (offset < 0 || offset > source.length - SIZE) {
            throw new IllegalArgumentException("need " + SIZE + " bytes at offset " + offset);
        }
        return new Hash32(Arrays.copyOfRange(source, offset, offset + SIZE));
    }

    /** Creates a hash from exactly 32 bytes in internal order. */
    public static Hash32 fromInternal(byte[] internalBytes) {
        if (internalBytes.length != SIZE) {
            throw new IllegalArgumentException("a hash is " + SIZE + " bytes, got " + internalBytes.length);
        }
        return new Hash32(internalBytes.clone());
    }

    /** Parses 64 hex digits in display order, as shown by block explorers. */
    public static Hash32 fromDisplayHex(String hex) {
        byte[] display = Hex.decode(hex.trim());
        if (display.length != SIZE) {
            throw new IllegalArgumentException("a hash is 64 hex digits, got " + display.length * 2);
        }
        return new Hash32(reversed(display));
    }

    /** Copies the internal-order bytes into {@code target} at {@code offset}. */
    public void copyInternalTo(byte[] target, int offset) {
        System.arraycopy(bytes, 0, target, offset, SIZE);
    }

    /** Returns a copy of the bytes in internal order. */
    public byte[] internalBytes() {
        return bytes.clone();
    }

    /** Returns the hash as 64 hex digits in display order. */
    public String toDisplayHex() {
        return Hex.encode(reversed(bytes));
    }

    /** Returns the hash as 64 hex digits in internal order. */
    public String toInternalHex() {
        return Hex.encode(bytes);
    }

    private static byte[] reversed(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length - 1 - i];
        }
        return out;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Hash32 h && Arrays.equals(bytes, h.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return toDisplayHex();
    }
}
