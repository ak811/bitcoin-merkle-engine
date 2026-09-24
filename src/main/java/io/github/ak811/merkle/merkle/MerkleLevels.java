package io.github.ak811.merkle.merkle;

import io.github.ak811.merkle.crypto.Hash32;
import io.github.ak811.merkle.crypto.Sha256d;

/**
 * The Bitcoin Merkle level function.
 *
 * <p>A level of {@code count} hashes is stored as one flat array of {@code 32 * count} bytes.
 * The next level has {@code ceil(count / 2)} hashes: node {@code p} is
 * {@code SHA256d(level[2p] || level[2p + 1])}. When {@code count} is odd, the last hash is
 * paired with itself, exactly as in Bitcoin Core.
 *
 * <p>Pairing the last hash with itself makes the lists {@code [a, b, c]} and {@code [a, b, c, c]}
 * produce the same root (CVE-2012-2459). Following Bitcoin Core, a level is reported as
 * <i>mutated</i> when two real, adjacent hashes at positions {@code 2p} and {@code 2p + 1} are equal.
 */
public final class MerkleLevels {

    private MerkleLevels() {
    }

    /** Number of hashes in the level above a level of {@code count} hashes. */
    public static int parentCount(int count) {
        return (count + 1) >>> 1;
    }

    /**
     * Computes parents {@code [fromParent, toParent)} of a level into {@code out}.
     *
     * @return true if any pair in the range consists of two equal, distinct-position hashes
     */
    public static boolean hashParents(byte[] level, int count, byte[] out, int fromParent, int toParent) {
        boolean mutated = false;
        for (int p = fromParent; p < toParent; p++) {
            int left = 2 * p;
            int right = left + 1 < count ? left + 1 : left;
            int leftOffset = left * Hash32.SIZE;
            int rightOffset = right * Hash32.SIZE;
            if (right != left && equal(level, leftOffset, rightOffset)) {
                mutated = true;
            }
            Sha256d.hashPair(level, leftOffset, rightOffset, out, p * Hash32.SIZE);
        }
        return mutated;
    }

    private static boolean equal(byte[] level, int a, int b) {
        for (int i = 0; i < Hash32.SIZE; i++) {
            if (level[a + i] != level[b + i]) {
                return false;
            }
        }
        return true;
    }
}
