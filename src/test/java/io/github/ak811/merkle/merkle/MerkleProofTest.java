package io.github.ak811.merkle.merkle;

import io.github.ak811.merkle.crypto.Hash32;
import io.github.ak811.merkle.io.TxidFile;
import io.github.ak811.merkle.io.TxidList;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MerkleProofTest {

    @Test
    void everyLeafHasAValidProofForManyTreeSizes() {
        try (LevelHasher hasher = new ParallelLevelHasher(3)) {
            for (int n = 1; n <= 70; n++) {
                TxidList txids = TxidFile.random(n, 100 + n);
                MerkleTree tree = MerkleTree.build(txids.leaves(), n, hasher);
                assertEquals(MerkleRoot.compute(txids.leaves(), n, hasher).root(), tree.root());
                for (int i = 0; i < n; i++) {
                    MerkleProof proof = tree.proof(i);
                    assertTrue(proof.verify(txids.get(i), tree.root()), "n=" + n + ", i=" + i);
                    assertEquals(32 - Integer.numberOfLeadingZeros(n - 1), proof.siblings().size());
                }
            }
        }
    }

    @Test
    void rejectsTamperedProofsWrongLeavesAndWrongPositions() {
        TxidList txids = TxidFile.random(37, 9);
        MerkleTree tree = MerkleTree.build(txids.leaves(), 37, new SequentialLevelHasher());
        MerkleProof proof = tree.proof(20);

        assertFalse(proof.verify(txids.get(21), tree.root()), "wrong leaf");
        assertFalse(new MerkleProof(21, proof.siblings()).verify(txids.get(20), tree.root()), "wrong index");
        List<Hash32> tampered = new ArrayList<>(proof.siblings());
        tampered.set(2, txids.get(0));
        assertFalse(new MerkleProof(20, tampered).verify(txids.get(20), tree.root()), "tampered sibling");
        assertFalse(proof.verify(txids.get(20), Hash32.ZERO), "wrong root");
    }

    @Test
    void textFormatRoundTrips() {
        TxidList txids = TxidFile.random(9, 4);
        MerkleTree tree = MerkleTree.build(txids.leaves(), 9, new SequentialLevelHasher());
        MerkleProof proof = tree.proof(8);
        MerkleProof parsed = MerkleProof.parse("# comment\n\n" + proof.toText());
        assertEquals(proof, parsed);
        assertTrue(parsed.verify(txids.get(8), tree.root()));
    }

    @Test
    void rejectsMalformedProofs() {
        assertThrows(IllegalArgumentException.class, () -> MerkleProof.parse(""));
        assertThrows(IllegalArgumentException.class, () -> MerkleProof.parse("idx 3\n"));
        assertThrows(IllegalArgumentException.class, () -> MerkleProof.parse("index 1\nnot-a-hash\n"));
        assertThrows(IllegalArgumentException.class, () -> new MerkleProof(4, List.of(Hash32.ZERO, Hash32.ZERO)));
    }

    @Test
    void treeLookupsWork() {
        TxidList txids = TxidFile.random(5, 1);
        MerkleTree tree = MerkleTree.build(txids.leaves(), 5, new SequentialLevelHasher());
        assertEquals(3, tree.indexOf(txids.get(3)));
        assertEquals(-1, tree.indexOf(Hash32.ZERO));
        assertEquals(txids.get(4), tree.leaf(4));
        assertThrows(IndexOutOfBoundsException.class, () -> tree.proof(5));
        assertEquals(Hash32.ZERO, MerkleTree.build(new byte[0], 0, new SequentialLevelHasher()).root());
    }
}
