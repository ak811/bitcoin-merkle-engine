package io.github.ak811.merkle.merkle;

import io.github.ak811.merkle.crypto.Hash32;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A fully materialized Merkle tree, keeping every level so that inclusion proofs can be
 * generated for any leaf. It uses about twice the memory of the leaves; to compute only a
 * root, {@link MerkleRoot} needs far less.
 */
public final class MerkleTree {

    private final List<byte[]> levels;
    private final int[] counts;
    private final boolean mutated;

    private MerkleTree(List<byte[]> levels, int[] counts, boolean mutated) {
        this.levels = levels;
        this.counts = counts;
        this.mutated = mutated;
    }

    /** Builds the tree over {@code count} leaves. The leaves are copied. */
    public static MerkleTree build(byte[] leaves, int count, LevelHasher hasher) {
        Objects.requireNonNull(hasher, "hasher");
        MerkleRoot.checkLeaves(leaves, count);
        List<byte[]> levels = new ArrayList<>();
        List<Integer> counts = new ArrayList<>();
        byte[] level = java.util.Arrays.copyOf(leaves, count * Hash32.SIZE);
        levels.add(level);
        counts.add(count);
        boolean mutated = false;
        while (count > 1) {
            int parents = MerkleLevels.parentCount(count);
            byte[] next = new byte[parents * Hash32.SIZE];
            mutated |= hasher.hashLevel(level, count, next);
            levels.add(next);
            counts.add(parents);
            level = next;
            count = parents;
        }
        return new MerkleTree(levels, counts.stream().mapToInt(Integer::intValue).toArray(), mutated);
    }

    public int leafCount() {
        return counts[0];
    }

    /** The root, or {@link Hash32#ZERO} for an empty tree. */
    public Hash32 root() {
        return leafCount() == 0 ? Hash32.ZERO : Hash32.fromInternal(levels.get(levels.size() - 1), 0);
    }

    public boolean mutated() {
        return mutated;
    }

    public Hash32 leaf(int index) {
        Objects.checkIndex(index, leafCount());
        return Hash32.fromInternal(levels.get(0), index * Hash32.SIZE);
    }

    /** Returns the index of the first leaf equal to {@code hash}, or -1. */
    public int indexOf(Hash32 hash) {
        byte[] target = hash.internalBytes();
        byte[] leaves = levels.get(0);
        outer:
        for (int i = 0; i < leafCount(); i++) {
            int offset = i * Hash32.SIZE;
            for (int b = 0; b < Hash32.SIZE; b++) {
                if (leaves[offset + b] != target[b]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** Builds the inclusion proof for the leaf at {@code index}. */
    public MerkleProof proof(int index) {
        Objects.checkIndex(index, leafCount());
        List<Hash32> siblings = new ArrayList<>(levels.size() - 1);
        int position = index;
        for (int level = 0; level < levels.size() - 1; level++) {
            int sibling = position ^ 1;
            if (sibling >= counts[level]) {
                sibling = position; // The last hash of an odd level is paired with itself.
            }
            siblings.add(Hash32.fromInternal(levels.get(level), sibling * Hash32.SIZE));
            position >>>= 1;
        }
        return new MerkleProof(index, siblings);
    }
}
