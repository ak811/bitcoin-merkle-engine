package io.github.ak811.merkle.cli;

import io.github.ak811.merkle.TestData;
import io.github.ak811.merkle.crypto.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppTest {

    @TempDir
    Path dir;

    private record Run(int status, String out, String err) {
    }

    private static Run run(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int status;
        try (PrintStream o = new PrintStream(out, true, StandardCharsets.UTF_8);
             PrintStream e = new PrintStream(err, true, StandardCharsets.UTF_8)) {
            status = App.run(args, o, e);
        }
        return new Run(status, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    private static final String TX_2 = "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4";

    @Test
    void rootPrintsTheMerkleRoot() {
        Run r = run("root", TestData.resource("txids/block-100000.txt").toString(), "--threads", "2");
        assertEquals(App.EXIT_OK, r.status(), r.err());
        assertTrue(r.out().startsWith(TestData.BLOCK_100000_ROOT + "\n"), r.out());
    }

    @Test
    void proofThenVerifyRoundTrips() {
        Path proof = dir.resolve("proof.txt");
        String txids = TestData.resource("txids/block-100000.txt").toString();

        Run made = run("proof", txids, "--txid", TX_2, "--out", proof.toString());
        assertEquals(App.EXIT_OK, made.status(), made.err());

        Run ok = run("verify", proof.toString(), "--txid", TX_2, "--root", TestData.BLOCK_100000_ROOT);
        assertEquals(App.EXIT_OK, ok.status(), ok.out() + ok.err());
        assertTrue(ok.out().startsWith("VALID"), ok.out());

        Run bad = run("verify", proof.toString(), "--txid", TX_2, "--root", "00".repeat(32));
        assertEquals(App.EXIT_INVALID, bad.status());
        assertTrue(bad.out().startsWith("INVALID"), bad.out());
    }

    @Test
    void blockCommandVerifiesRealBlocksAndFlagsTampering() throws Exception {
        Run ok = run("block", TestData.resource("blocks/mainnet-542213-segwit.hex").toString(), "--list-txids");
        assertEquals(App.EXIT_OK, ok.status(), ok.err());
        assertTrue(ok.out().contains("Result: VALID"), ok.out());

        byte[] data = TestData.block("testnet-3kib");
        data[76] ^= 1; // nonce
        Path tampered = dir.resolve("tampered.hex");
        Files.writeString(tampered, Hex.encode(data));
        Run bad = run("block", tampered.toString());
        assertEquals(App.EXIT_INVALID, bad.status());
        assertTrue(bad.out().contains("Result: INVALID"), bad.out());
    }

    @Test
    void benchAndGenerateRun() throws Exception {
        Run bench = run("bench", "--leaves", "5000", "--thread-counts", "1,2", "--warmup", "0", "--repeat", "1");
        assertEquals(App.EXIT_OK, bench.status(), bench.err());
        assertTrue(bench.out().contains("All strategies computed the same root."), bench.out());

        Path file = dir.resolve("random.txt");
        Run gen = run("generate", file.toString(), "--count", "300", "--seed", "5");
        assertEquals(App.EXIT_OK, gen.status(), gen.err());
        assertEquals(300, Files.readAllLines(file).size());
    }

    @Test
    void reportsUsageErrorsAndMissingFiles() {
        assertEquals(App.EXIT_USAGE, run().status());
        assertEquals(App.EXIT_OK, run("--help").status());
        assertEquals(App.EXIT_USAGE, run("mine").status());
        assertEquals(App.EXIT_USAGE, run("root").status());
        assertEquals(App.EXIT_USAGE, run("root", "x.txt", "--bogus").status());
        assertEquals(App.EXIT_USAGE, run("proof", "x.txt").status());
        assertEquals(App.EXIT_USAGE, run("bench", "--thread-counts", "0").status());

        Run missing = run("root", dir.resolve("missing.txt").toString());
        assertEquals(App.EXIT_ERROR, missing.status());
        assertTrue(missing.err().contains("file not found"), missing.err());
    }
}
