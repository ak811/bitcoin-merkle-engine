package io.github.ak811.merkle.bitcoin;

import io.github.ak811.merkle.concurrent.WorkerPool;
import io.github.ak811.merkle.crypto.Hash32;
import io.github.ak811.merkle.crypto.Hex;
import io.github.ak811.merkle.crypto.Sha256d;
import io.github.ak811.merkle.merkle.LevelHasher;
import io.github.ak811.merkle.merkle.MerkleResult;
import io.github.ak811.merkle.merkle.MerkleRoot;
import io.github.ak811.merkle.merkle.ParallelLevelHasher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Verifies that a block's transactions match the commitments in its header.
 *
 * <p>Checks performed:
 * <ol>
 *   <li><b>Merkle root:</b> every txid is recomputed from the raw transaction, the Merkle root is
 *       rebuilt, and it must equal the header's root.</li>
 *   <li><b>Mutation:</b> the transaction list must not have the duplicate-pair shape of
 *       CVE-2012-2459, which lets a different list produce the same root.</li>
 *   <li><b>Proof of work:</b> the block hash must not exceed the target encoded in the header.</li>
 *   <li><b>Witness commitment (BIP 141):</b> if the block contains SegWit transactions or a
 *       commitment, the Merkle root of the wtxids, combined with the coinbase's witness reserved
 *       value, must match the commitment in the coinbase output.</li>
 * </ol>
 * Transaction hashing and Merkle levels are computed in parallel on a shared {@link WorkerPool}.
 */
public final class BlockVerifier {

    /** Script prefix of a witness commitment output: OP_RETURN, push 36, and the tag aa21a9ed. */
    private static final byte[] COMMITMENT_PREFIX = Hex.decode("6a24aa21a9ed");
    private static final int COMMITMENT_SCRIPT_MIN_LENGTH = 38;

    /** Transactions per chunk below which txid hashing is not split further. */
    private static final int MIN_TRANSACTIONS_PER_CHUNK = 16;

    private final WorkerPool pool;

    public BlockVerifier(WorkerPool pool) {
        this.pool = Objects.requireNonNull(pool, "pool");
    }

    public BlockReport verify(Block block) {
        byte[] data = block.data();
        List<TransactionLayout> transactions = block.transactions();
        int n = transactions.size();

        byte[] txids = new byte[n * Hash32.SIZE];
        pool.anyMatch(n, MIN_TRANSACTIONS_PER_CHUNK, (from, to) -> {
            for (int i = from; i < to; i++) {
                txid(data, transactions.get(i), txids, i * Hash32.SIZE);
            }
            return false;
        });

        MerkleResult merkle;
        try (LevelHasher hasher = new ParallelLevelHasher(pool)) {
            merkle = MerkleRoot.compute(txids, n, hasher);
        }

        List<Hash32> ids = new ArrayList<>(n);
        int segwit = 0;
        for (int i = 0; i < n; i++) {
            ids.add(Hash32.fromInternal(txids, i * Hash32.SIZE));
            if (transactions.get(i).segwit()) {
                segwit++;
            }
        }
        WitnessCheck witness = checkWitnessCommitment(data, transactions, segwit);
        return new BlockReport(block.header(), ids, segwit, merkle.root(), merkle.mutated(), witness);
    }

    /** Hashes a transaction's non-witness serialization into {@code out}. */
    private static void txid(byte[] data, TransactionLayout tx, byte[] out, int outOffset) {
        if (!tx.segwit()) {
            Sha256d.hashInto(data, tx.start(), tx.length(), out, outOffset);
        } else {
            // version | inputs and outputs (skipping marker and flag) | lock time
            Sha256d.hashRanges(data,
                    tx.start(), 4,
                    tx.start() + 6, tx.witnessStart() - (tx.start() + 6),
                    tx.witnessEnd(), tx.end() - tx.witnessEnd(),
                    out, outOffset);
        }
    }

    private WitnessCheck checkWitnessCommitment(byte[] data, List<TransactionLayout> transactions, int segwit) {
        TransactionLayout coinbase = transactions.get(0);
        int[] commitment = null;
        for (int[] script : coinbase.outputScripts()) { // The last matching output counts.
            if (script[1] >= COMMITMENT_SCRIPT_MIN_LENGTH && startsWith(data, script[0], COMMITMENT_PREFIX)) {
                commitment = script;
            }
        }
        if (commitment == null) {
            return segwit == 0
                    ? new WitnessCheck(WitnessCheck.Status.NOT_APPLICABLE, "no SegWit transactions")
                    : new WitnessCheck(WitnessCheck.Status.INVALID,
                            segwit + " SegWit transactions but no witness commitment");
        }
        List<int[]> reserved = coinbase.firstInputWitness();
        if (reserved.size() != 1 || reserved.get(0)[1] != Hash32.SIZE) {
            return new WitnessCheck(WitnessCheck.Status.INVALID,
                    "coinbase witness must hold exactly one 32-byte reserved value");
        }

        // wtxids: the coinbase's is defined as zero; others hash the full serialization.
        int n = transactions.size();
        byte[] wtxids = new byte[n * Hash32.SIZE];
        pool.anyMatch(n, MIN_TRANSACTIONS_PER_CHUNK, (from, to) -> {
            for (int i = Math.max(from, 1); i < to; i++) {
                TransactionLayout tx = transactions.get(i);
                Sha256d.hashInto(data, tx.start(), tx.length(), wtxids, i * Hash32.SIZE);
            }
            return false;
        });
        Hash32 witnessRoot;
        try (LevelHasher hasher = new ParallelLevelHasher(pool)) {
            witnessRoot = MerkleRoot.compute(wtxids, n, hasher).root();
        }

        byte[] preimage = new byte[2 * Hash32.SIZE];
        witnessRoot.copyInternalTo(preimage, 0);
        System.arraycopy(data, reserved.get(0)[0], preimage, Hash32.SIZE, Hash32.SIZE);
        Hash32 expected = Sha256d.hash(preimage);
        byte[] actual = Arrays.copyOfRange(data, commitment[0] + COMMITMENT_PREFIX.length,
                commitment[0] + COMMITMENT_PREFIX.length + Hash32.SIZE);
        return Arrays.equals(expected.internalBytes(), actual)
                ? new WitnessCheck(WitnessCheck.Status.VALID, "commitment " + Hex.encode(actual) + " matches")
                : new WitnessCheck(WitnessCheck.Status.INVALID,
                        "commitment " + Hex.encode(actual) + " does not match " + expected.toInternalHex());
    }

    private static boolean startsWith(byte[] data, int offset, byte[] prefix) {
        for (int i = 0; i < prefix.length; i++) {
            if (data[offset + i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}
