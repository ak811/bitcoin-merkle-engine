package io.github.ak811.merkle.bitcoin;

import io.github.ak811.merkle.crypto.Hash32;

import java.util.List;

/**
 * Result of verifying a block's transaction commitments and proof of work.
 *
 * @param header             the parsed header
 * @param txids              transaction IDs in block order
 * @param segwitTransactions number of transactions using the SegWit serialization
 * @param computedMerkleRoot Merkle root recomputed from the transactions
 * @param mutated            whether the transaction list has the CVE-2012-2459 duplicate-pair shape
 * @param witness            outcome of the SegWit witness commitment check
 */
public record BlockReport(BlockHeader header, List<Hash32> txids, int segwitTransactions,
                          Hash32 computedMerkleRoot, boolean mutated, WitnessCheck witness) {

    public BlockReport {
        txids = List.copyOf(txids);
    }

    /** Whether the recomputed Merkle root equals the one in the header. */
    public boolean merkleRootMatches() {
        return computedMerkleRoot.equals(header.merkleRoot());
    }

    /** Whether the block passes every check performed. */
    public boolean valid() {
        return merkleRootMatches() && !mutated && header.hasValidProofOfWork() && witness.passed();
    }
}
