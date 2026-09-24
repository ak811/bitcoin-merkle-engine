package io.github.ak811.merkle.io;

import io.github.ak811.merkle.crypto.Hash32;

import java.util.Objects;

/**
 * A list of transaction IDs stored contiguously as 32-byte hashes in internal byte order,
 * ready to be used as Merkle leaves.
 *
 * @param leaves {@code 32 * count} bytes
 * @param count  number of txids
 */
public record TxidList(byte[] leaves, int count) {

    public TxidList {
        Objects.requireNonNull(leaves, "leaves");
        if (count < 0 || (long) count * Hash32.SIZE != leaves.length) {
            throw new IllegalArgumentException(count + " txids need " + (long) count * Hash32.SIZE
                    + " bytes, got " + leaves.length);
        }
    }

    public Hash32 get(int index) {
        Objects.checkIndex(index, count);
        return Hash32.fromInternal(leaves, index * Hash32.SIZE);
    }
}
