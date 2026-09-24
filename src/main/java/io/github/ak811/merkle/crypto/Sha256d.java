package io.github.ak811.merkle.crypto;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Double SHA-256, {@code SHA256(SHA256(x))}, the hash Bitcoin uses for transaction IDs,
 * block hashes, and Merkle tree nodes.
 *
 * <p>Each thread reuses its own {@link MessageDigest}, so hashing is allocation-free on hot
 * paths and safe to call from many threads at once.
 */
public final class Sha256d {

    private static final ThreadLocal<State> STATE = ThreadLocal.withInitial(State::new);

    private Sha256d() {
    }

    /** Returns {@code SHA256(SHA256(data[offset, offset + length)))}. */
    public static Hash32 hash(byte[] data, int offset, int length) {
        byte[] out = new byte[Hash32.SIZE];
        hashInto(data, offset, length, out, 0);
        return Hash32.fromInternal(out, 0);
    }

    /** Returns the double SHA-256 of all of {@code data}. */
    public static Hash32 hash(byte[] data) {
        return hash(data, 0, data.length);
    }

    /** Writes {@code SHA256(SHA256(data[offset, offset + length)))} into {@code out[outOffset, outOffset + 32)}. */
    public static void hashInto(byte[] data, int offset, int length, byte[] out, int outOffset) {
        State state = STATE.get();
        state.digest.update(data, offset, length);
        state.finish(out, outOffset);
    }

    /**
     * Writes the double SHA-256 of the concatenation of three byte ranges of {@code data} into
     * {@code out}, without copying them. Used to hash a SegWit transaction without its witness data.
     */
    public static void hashRanges(byte[] data, int offset1, int length1, int offset2, int length2,
                                  int offset3, int length3, byte[] out, int outOffset) {
        State state = STATE.get();
        state.digest.update(data, offset1, length1);
        state.digest.update(data, offset2, length2);
        state.digest.update(data, offset3, length3);
        state.finish(out, outOffset);
    }

    /**
     * Writes {@code SHA256(SHA256(left || right))} into {@code out}, where {@code left} and
     * {@code right} are 32-byte hashes. This is the Merkle tree node function.
     */
    public static void hashPair(byte[] source, int leftOffset, int rightOffset, byte[] out, int outOffset) {
        State state = STATE.get();
        state.digest.update(source, leftOffset, Hash32.SIZE);
        state.digest.update(source, rightOffset, Hash32.SIZE);
        state.finish(out, outOffset);
    }

    private static final class State {
        final MessageDigest digest;
        final byte[] first = new byte[Hash32.SIZE];

        State() {
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 is required by every Java platform", e);
            }
        }

        void finish(byte[] out, int outOffset) {
            try {
                digest.digest(first, 0, Hash32.SIZE);
                digest.update(first, 0, Hash32.SIZE);
                digest.digest(out, outOffset, Hash32.SIZE);
            } catch (DigestException e) {
                throw new IllegalStateException("SHA-256 digest failed", e);
            }
        }
    }
}
