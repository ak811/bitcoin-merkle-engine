package io.github.ak811.merkle.io;

import io.github.ak811.merkle.TestData;
import io.github.ak811.merkle.crypto.Hash32;
import io.github.ak811.merkle.crypto.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FilesTest {

    @TempDir
    Path dir;

    @Test
    void readsTxidsInDisplayOrderSkippingCommentsAndBlankLines() throws IOException {
        TxidList txids = TxidFile.read(TestData.resource("txids/block-100000.txt"));
        assertEquals(4, txids.count());
        assertEquals(Hash32.fromDisplayHex("8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87"), txids.get(0));
    }

    @Test
    void writeThenReadRoundTrips() throws IOException {
        TxidList txids = TxidFile.random(5_000, 8); // more than the initial read buffer
        Path file = dir.resolve("txids.txt");
        TxidFile.write(file, txids);
        assertArrayEquals(txids.leaves(), TxidFile.read(file).leaves());
    }

    @Test
    void reportsTheLineOfAnInvalidTxid() throws IOException {
        Path file = dir.resolve("bad.txt");
        Files.writeString(file, "# header\n" + "ab".repeat(32) + "\nnot-a-txid\n");
        IOException e = assertThrows(IOException.class, () -> TxidFile.read(file));
        assertTrue(e.getMessage().contains("line 3"), e.getMessage());
    }

    @Test
    void randomTxidsAreDeterministic() {
        assertArrayEquals(TxidFile.random(100, 1).leaves(), TxidFile.random(100, 1).leaves());
    }

    @Test
    void readsBlocksAsHexOrRawBytes() throws IOException {
        byte[] raw = TestData.block("genesis");
        Path hex = dir.resolve("genesis.hex");
        Path bin = dir.resolve("genesis.dat");
        Files.writeString(hex, Hex.encode(raw) + "\n");
        Files.write(bin, raw);
        assertArrayEquals(raw, BlockFile.read(hex));
        assertArrayEquals(raw, BlockFile.read(bin));
    }
}
