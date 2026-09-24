package io.github.ak811.merkle.merkle;

import io.github.ak811.merkle.crypto.Hash32;

/**
 * A computed Merkle root.
 *
 * @param root    the root hash
 * @param mutated true if the tree contains a duplicated adjacent pair, meaning another,
 *                shorter transaction list produces the same root (see {@link MerkleLevels})
 */
public record MerkleResult(Hash32 root, boolean mutated) {
}
