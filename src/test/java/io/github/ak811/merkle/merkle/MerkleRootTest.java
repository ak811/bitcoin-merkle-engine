package io.github.ak811.merkle.merkle;

import io.github.ak811.merkle.TestData;
import io.github.ak811.merkle.crypto.Hash32;
import io.github.ak811.merkle.crypto.Sha256d;
import io.github.ak811.merkle.io.TxidFile;
import io.github.ak811.merkle.io.TxidList;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MerkleRootTest {

    /** Reference implementation written independently of MerkleLevels, following Bitcoin Core. */
    private static Hash32 reference(Hash32[] leaves) {
        if (leaves.length == 0) {
            return Hash32.ZERO;
        }
        Hash32[] level = leaves;
        while (level.length > 1) {
            Hash32[] next = new Hash32[(level.length + 1) / 2];
            for (int i = 0; i < next.length; i++) {
                Hash32 left = level[2 * i];
                Hash32 right = 2 * i + 1 < level.length ? level[2 * i + 1] : left;
                byte[] pair = new byte[64];
                left.copyInternalTo(pair, 0);
                right.copyInternalTo(pair, 32);
                next[i] = Sha256d.hash(pair);
            }
            level = next;
        }
        return level[0];
    }

    private static Hash32[] split(TxidList list) {
        Hash32[] out = new Hash32[list.count()];
        for (int i = 0; i < out.length; i++) {
            out[i] = list.get(i);
        }
        return out;
    }

    @Test
    void matchesBitcoinBlock100000() throws IOException {
        TxidList txids = TxidFile.read(TestData.resource("txids/block-100000.txt"));
        Hash32 expected = Hash32.fromDisplayHex(TestData.BLOCK_100000_ROOT);
        try (LevelHasher sequential = new SequentialLevelHasher();
             LevelHasher parallel = new ParallelLevelHasher(3)) {
            assertEquals(expected, MerkleRoot.compute(txids.leaves(), txids.count(), sequential).root());
            assertEquals(expected, MerkleRoot.compute(txids.leaves(), txids.count(), parallel).root());
        }
    }

    @Test
    void emptyAndSingleLeafFollowBitcoinConventions() {
        try (LevelHasher hasher = new SequentialLevelHasher()) {
            assertEquals(Hash32.ZERO, MerkleRoot.compute(new byte[0], 0, hasher).root());
            TxidList one = TxidFile.random(1, 3);
            assertEquals(one.get(0), MerkleRoot.compute(one.leaves(), 1, hasher).root());
        }
    }

    @Test
    void sequentialAndParallelAgreeWithTheReferenceForManySizes() {
        try (LevelHasher sequential = new SequentialLevelHasher();
             LevelHasher parallel2 = new ParallelLevelHasher(2);
             LevelHasher parallel5 = new ParallelLevelHasher(5)) {
            for (int n = 0; n <= 130; n++) {
                TxidList txids = TxidFile.random(n, n);
                Hash32 expected = reference(split(txids));
                for (LevelHasher hasher : new LevelHasher[] {sequential, parallel2, parallel5}) {
                    assertEquals(expected, MerkleRoot.compute(txids.leaves(), n, hasher).root(), "n=" + n);
                }
            }
        }
    }

    @Test
    void parallelMatchesSequentialOnLargeTreesThatUseEveryThread() {
        // Large enough that several levels exceed ParallelLevelHasher.MIN_PARENTS_PER_CHUNK per thread.
        for (int n : new int[] {100_000, 131_073, 262_144}) {
            TxidList txids = TxidFile.random(n, 11);
            byte[] before = txids.leaves().clone();
            try (LevelHasher sequential = new SequentialLevelHasher();
                 LevelHasher parallel = new ParallelLevelHasher(8)) {
                MerkleResult expected = MerkleRoot.compute(txids.leaves(), n, sequential);
                assertEquals(expected, MerkleRoot.compute(txids.leaves(), n, parallel), "n=" + n);
            }
            assertArrayEquals(before, txids.leaves(), "input must not be modified");
        }
    }

    @Test
    void detectsTheDuplicatePairMutation() {
        // CVE-2012-2459: [a, b, c] and [a, b, c, c] have the same root; only the second is flagged.
        TxidList abc = TxidFile.random(3, 5);
        byte[] abcc = Arrays.copyOf(abc.leaves(), 4 * 32);
        System.arraycopy(abc.leaves(), 64, abcc, 96, 32);
        try (LevelHasher parallel = new ParallelLevelHasher(4)) {
            MerkleResult original = MerkleRoot.compute(abc.leaves(), 3, parallel);
            MerkleResult mutated = MerkleRoot.compute(abcc, 4, parallel);
            assertEquals(original.root(), mutated.root());
            assertFalse(original.mutated());
            assertTrue(mutated.mutated());
        }
    }

    @Test
    void rejectsInconsistentInput() {
        try (LevelHasher hasher = new SequentialLevelHasher()) {
            assertThrows(IllegalArgumentException.class, () -> MerkleRoot.compute(new byte[31], 1, hasher));
            assertThrows(IllegalArgumentException.class, () -> MerkleRoot.compute(new byte[32], -1, hasher));
        }
    }
}
