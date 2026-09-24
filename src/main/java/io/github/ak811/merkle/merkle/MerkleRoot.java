package io.github.ak811.merkle.merkle;

import io.github.ak811.merkle.crypto.Hash32;

import java.util.Objects;

/**
 * Computes a Bitcoin-compatible Merkle root while keeping only two levels in memory.
 *
 * <p>Leaves are 32-byte hashes in internal byte order, stored contiguously. The root of an
 * empty list is {@link Hash32#ZERO}, and the root of a single leaf is that leaf.
 */
public final class MerkleRoot {

    private MerkleRoot() {
    }

    /** Computes the root of {@code count} leaves stored in {@code leaves}. The input is not modified. */
    public static MerkleResult compute(byte[] leaves, int count, LevelHasher hasher) {
        Objects.requireNonNull(hasher, "hasher");
        checkLeaves(leaves, count);
        if (count == 0) {
            return new MerkleResult(Hash32.ZERO, false);
        }
        // Alternate between two buffers. Levels shrink, so the buffer allocated for the first
        // parent level is large enough for every later level written into it.
        byte[] current = leaves;
        byte[] bufferA = null;
        byte[] bufferB = null;
        boolean mutated = false;
        while (count > 1) {
            int parents = MerkleLevels.parentCount(count);
            byte[] next;
            if (current == bufferA) {
                if (bufferB == null) {
                    bufferB = new byte[parents * Hash32.SIZE];
                }
                next = bufferB;
            } else {
                if (bufferA == null) {
                    bufferA = new byte[parents * Hash32.SIZE];
                }
                next = bufferA;
            }
            mutated |= hasher.hashLevel(current, count, next);
            current = next;
            count = parents;
        }
        return new MerkleResult(Hash32.fromInternal(current, 0), mutated);
    }

    static void checkLeaves(byte[] leaves, int count) {
        Objects.requireNonNull(leaves, "leaves");
        if (count < 0 || (long) count * Hash32.SIZE > leaves.length) {
            throw new IllegalArgumentException(count + " leaves do not fit in " + leaves.length + " bytes");
        }
    }
}
