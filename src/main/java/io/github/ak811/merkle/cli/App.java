package io.github.ak811.merkle.cli;

import io.github.ak811.merkle.bench.Benchmark;
import io.github.ak811.merkle.bitcoin.Block;
import io.github.ak811.merkle.bitcoin.BlockFormatException;
import io.github.ak811.merkle.bitcoin.BlockReport;
import io.github.ak811.merkle.bitcoin.BlockVerifier;
import io.github.ak811.merkle.concurrent.ParallelExecutionException;
import io.github.ak811.merkle.concurrent.WorkerPool;
import io.github.ak811.merkle.crypto.Hash32;
import io.github.ak811.merkle.io.BlockFile;
import io.github.ak811.merkle.io.TxidFile;
import io.github.ak811.merkle.io.TxidList;
import io.github.ak811.merkle.merkle.LevelHasher;
import io.github.ak811.merkle.merkle.MerkleProof;
import io.github.ak811.merkle.merkle.MerkleResult;
import io.github.ak811.merkle.merkle.MerkleRoot;
import io.github.ak811.merkle.merkle.MerkleTree;
import io.github.ak811.merkle.merkle.ParallelLevelHasher;
import io.github.ak811.merkle.merkle.SequentialLevelHasher;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Command-line entry point. */
public final class App {

    static final int EXIT_OK = 0;
    static final int EXIT_ERROR = 1;
    static final int EXIT_USAGE = 2;
    static final int EXIT_INVALID = 4;

    static final String USAGE = """
            Usage: java -jar blockchain-transaction-concurrency.jar <command> [options]

            Commands:
              root <txids-file>                      Compute the Merkle root of a list of txids
              proof <txids-file> (--index N | --txid HASH) [--out FILE]
                                                     Build an inclusion proof for one transaction
              verify <proof-file> --txid HASH --root HASH
                                                     Check an inclusion proof against a Merkle root
              block <block-file> [--list-txids]      Verify a raw block's Merkle root, witness
                                                     commitment, and proof of work
              bench [--leaves N] [--thread-counts 1,2,4] [--warmup N] [--repeat N] [--seed N]
                                                     Benchmark sequential vs. parallel root computation
              generate <out-file> --count N [--seed N]
                                                     Write N random txids for testing

            Options for root, proof, and block:
              --threads N    Worker threads (default: available processors)

            Txid files hold one 64-digit hex txid per line, in display order as shown by block
            explorers. Block files hold a serialized block as raw bytes or hex.

            Exit status: 0 success, 1 error, 2 invalid usage, 4 verification failed.
            """;

    private static final int DEFAULT_THREADS = Math.min(Runtime.getRuntime().availableProcessors(), WorkerPool.MAX_THREADS);

    private final PrintStream out;

    private App(PrintStream out) {
        this.out = out;
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help") || args[0].equals("help")) {
            (args.length == 0 ? err : out).print(USAGE);
            return args.length == 0 ? EXIT_USAGE : EXIT_OK;
        }
        App app = new App(out);
        try {
            return switch (args[0]) {
                case "root" -> app.root(args);
                case "proof" -> app.proof(args);
                case "verify" -> app.verify(args);
                case "block" -> app.block(args);
                case "bench" -> app.bench(args);
                case "generate" -> app.generate(args);
                default -> throw new Args.UsageException("unknown command: " + args[0]);
            };
        } catch (Args.UsageException e) {
            err.println("error: " + e.getMessage());
            err.print(USAGE);
            return EXIT_USAGE;
        } catch (NoSuchFileException e) {
            err.println("error: file not found: " + e.getFile());
            return EXIT_ERROR;
        } catch (IOException | BlockFormatException | IllegalArgumentException | ParallelExecutionException e) {
            err.println("error: " + e.getMessage());
            return EXIT_ERROR;
        }
    }

    private int root(String[] args) throws IOException {
        Args a = Args.parse(args, 1, Set.of("--threads"), Set.of());
        a.requirePositionals(1);
        TxidList txids = TxidFile.read(Path.of(a.positional(0, "txids file")));
        try (LevelHasher hasher = hasher(a)) {
            long start = System.nanoTime();
            MerkleResult result = MerkleRoot.compute(txids.leaves(), txids.count(), hasher);
            long nanos = System.nanoTime() - start;
            out.println(result.root().toDisplayHex());
            out.printf(Locale.US, "# %,d txids, %d thread(s), %.3f ms%n", txids.count(), hasher.threads(), nanos / 1e6);
            if (result.mutated()) {
                out.println("# WARNING: duplicate adjacent txids (CVE-2012-2459): another list has the same root");
            }
        }
        return EXIT_OK;
    }

    private int proof(String[] args) throws IOException {
        Args a = Args.parse(args, 1, Set.of("--threads", "--index", "--txid", "--out"), Set.of());
        a.requirePositionals(1);
        if (a.has("--index") == a.has("--txid")) {
            throw new Args.UsageException("give exactly one of --index or --txid");
        }
        TxidList txids = TxidFile.read(Path.of(a.positional(0, "txids file")));
        MerkleTree tree;
        try (LevelHasher hasher = hasher(a)) {
            tree = MerkleTree.build(txids.leaves(), txids.count(), hasher);
        }
        if (tree.leafCount() == 0) {
            throw new IllegalArgumentException("the txid list is empty");
        }
        int index;
        if (a.has("--index")) {
            index = a.intValue("--index", 0, 0, tree.leafCount() - 1);
        } else {
            index = tree.indexOf(Hash32.fromDisplayHex(a.value("--txid")));
            if (index < 0) {
                throw new IllegalArgumentException("txid not found in the list");
            }
        }
        MerkleProof proof = tree.proof(index);
        String text = "# txid " + tree.leaf(index).toDisplayHex() + "\n"
                + "# root " + tree.root().toDisplayHex() + "\n"
                + proof.toText();
        if (a.has("--out")) {
            Files.writeString(Path.of(a.value("--out")), text, StandardCharsets.US_ASCII);
            out.printf(Locale.US, "Wrote proof for leaf %,d of %,d (%d hashes) to %s%n",
                    index, tree.leafCount(), proof.siblings().size(), a.value("--out"));
        } else {
            out.print(text);
        }
        return EXIT_OK;
    }

    private int verify(String[] args) throws IOException {
        Args a = Args.parse(args, 1, Set.of("--txid", "--root"), Set.of());
        a.requirePositionals(1);
        MerkleProof proof = MerkleProof.parse(Files.readString(Path.of(a.positional(0, "proof file"))));
        Hash32 txid = Hash32.fromDisplayHex(a.value("--txid"));
        Hash32 root = Hash32.fromDisplayHex(a.value("--root"));
        Hash32 implied = proof.rootFor(txid);
        if (implied.equals(root)) {
            out.printf(Locale.US, "VALID: txid is included at index %,d (%d-hash proof)%n",
                    proof.index(), proof.siblings().size());
            return EXIT_OK;
        }
        out.println("INVALID: the proof leads to root " + implied.toDisplayHex());
        return EXIT_INVALID;
    }

    private int block(String[] args) throws IOException, BlockFormatException {
        Args a = Args.parse(args, 1, Set.of("--threads"), Set.of("--list-txids"));
        a.requirePositionals(1);
        byte[] data = BlockFile.read(Path.of(a.positional(0, "block file")));
        int threads = a.intValue("--threads", DEFAULT_THREADS, 1, WorkerPool.MAX_THREADS);
        long start = System.nanoTime();
        Block block = Block.parse(data);
        BlockReport report;
        try (WorkerPool pool = new WorkerPool(threads)) {
            report = new BlockVerifier(pool).verify(block);
        }
        long nanos = System.nanoTime() - start;

        var header = report.header();
        out.println("Block " + header.hash().toDisplayHex());
        out.printf(Locale.US, "  Size:          %,d bytes%n", data.length);
        out.printf(Locale.US, "  Transactions:  %,d (%,d SegWit)%n", report.txids().size(), report.segwitTransactions());
        out.println("  Previous:      " + header.prevBlock().toDisplayHex());
        out.println("  Timestamp:     " + Instant.ofEpochSecond(header.time()) + " (" + header.time() + ")");
        out.printf(Locale.US, "  Version:       0x%08x%n", header.version());
        out.println();
        out.println("  Header Merkle root:    " + header.merkleRoot().toDisplayHex());
        out.println("  Computed Merkle root:  " + report.computedMerkleRoot().toDisplayHex());
        out.println("  " + check(report.merkleRootMatches()) + " Merkle root matches the header");
        out.println("  " + check(!report.mutated()) + " No duplicate-pair mutation (CVE-2012-2459)");
        out.println("  " + check(header.hasValidProofOfWork()) + " Proof of work meets the header target"
                + String.format(Locale.US, " (bits 0x%08x)", header.bits()));
        out.println("  " + check(report.witness().passed()) + " Witness commitment: "
                + report.witness().status().name().toLowerCase(Locale.ROOT).replace('_', ' ')
                + " (" + report.witness().detail() + ")");
        out.println();
        out.printf(Locale.US, "  Result: %s  [%d thread(s), %.3f ms]%n",
                report.valid() ? "VALID" : "INVALID", threads, nanos / 1e6);
        if (a.has("--list-txids")) {
            out.println();
            for (Hash32 txid : report.txids()) {
                out.println(txid.toDisplayHex());
            }
        }
        return report.valid() ? EXIT_OK : EXIT_INVALID;
    }

    private int bench(String[] args) {
        Args a = Args.parse(args, 1,
                Set.of("--leaves", "--thread-counts", "--warmup", "--repeat", "--seed"), Set.of());
        a.requirePositionals(0);
        int leaves = a.intValue("--leaves", 1_000_000, 1, (Integer.MAX_VALUE - 8) / Hash32.SIZE);
        List<Integer> threadCounts = a.intList("--thread-counts", defaultThreadCounts(), 1, WorkerPool.MAX_THREADS);
        int warmup = a.intValue("--warmup", 3, 0, 1000);
        int repeat = a.intValue("--repeat", 5, 1, 1000);
        long seed = a.longValue("--seed", 42, Long.MIN_VALUE, Long.MAX_VALUE);

        TxidList txids = TxidFile.random(leaves, seed);
        long nodes = internalNodes(leaves);
        out.printf(Locale.US, "Merkle root benchmark: %,d leaves, %,d double-SHA-256 node hashes%n", leaves, nodes);
        out.printf(Locale.US, "Processors: %d available; JVM: %s %s; %d warm-up and %d timed runs each%n%n",
                Runtime.getRuntime().availableProcessors(), System.getProperty("java.vm.name"),
                System.getProperty("java.version"), warmup, repeat);
        out.printf(Locale.US, "  %-12s %11s %11s %9s %14s%n", "Strategy", "Min (ms)", "Median (ms)", "Speedup", "Hashes/s");

        List<Benchmark.Measurement<MerkleResult>> results = new ArrayList<>();
        double baseline = 0;
        for (int i = -1; i < threadCounts.size(); i++) {
            String label = i < 0 ? "sequential" : threadCounts.get(i) + " thread" + (threadCounts.get(i) == 1 ? "" : "s");
            try (LevelHasher hasher = i < 0 ? new SequentialLevelHasher() : new ParallelLevelHasher(threadCounts.get(i))) {
                var m = Benchmark.measure(() -> MerkleRoot.compute(txids.leaves(), txids.count(), hasher), warmup, repeat);
                results.add(m);
                if (i < 0) {
                    baseline = m.medianNanos();
                }
                out.printf(Locale.US, "  %-12s %11.2f %11.2f %8.2fx %14s%n", label, m.minNanos() / 1e6,
                        m.medianNanos() / 1e6, baseline / m.medianNanos(),
                        String.format(Locale.US, "%,.0f", nodes / (m.medianNanos() / 1e9)));
            }
        }
        boolean agree = results.stream().allMatch(r -> r.result().equals(results.get(0).result()));
        out.println();
        out.println("  Root: " + results.get(0).result().root().toDisplayHex());
        out.println(agree ? "  All strategies computed the same root." : "  ERROR: strategies disagree.");
        return agree ? EXIT_OK : EXIT_INVALID;
    }

    private int generate(String[] args) throws IOException {
        Args a = Args.parse(args, 1, Set.of("--count", "--seed"), Set.of());
        a.requirePositionals(1);
        Path file = Path.of(a.positional(0, "output file"));
        int count = a.intValue("--count", 0, 1, (Integer.MAX_VALUE - 8) / Hash32.SIZE);
        if (!a.has("--count")) {
            throw new Args.UsageException("--count is required");
        }
        TxidFile.write(file, TxidFile.random(count, a.longValue("--seed", 42, Long.MIN_VALUE, Long.MAX_VALUE)));
        out.printf(Locale.US, "Wrote %,d random txids to %s%n", count, file);
        return EXIT_OK;
    }

    private static LevelHasher hasher(Args a) {
        int threads = a.intValue("--threads", DEFAULT_THREADS, 1, WorkerPool.MAX_THREADS);
        return threads == 1 ? new SequentialLevelHasher() : new ParallelLevelHasher(threads);
    }

    private static List<Integer> defaultThreadCounts() {
        List<Integer> counts = new ArrayList<>();
        for (int t = 1; t <= DEFAULT_THREADS; t *= 2) {
            counts.add(t);
        }
        if (counts.get(counts.size() - 1) != DEFAULT_THREADS) {
            counts.add(DEFAULT_THREADS);
        }
        return counts;
    }

    /** Number of node hashes computed for a tree of {@code leaves} leaves. */
    static long internalNodes(int leaves) {
        long total = 0;
        for (long count = leaves; count > 1; count = (count + 1) / 2) {
            total += (count + 1) / 2;
        }
        return total;
    }

    private static String check(boolean ok) {
        return ok ? "[ok]  " : "[FAIL]";
    }
}
