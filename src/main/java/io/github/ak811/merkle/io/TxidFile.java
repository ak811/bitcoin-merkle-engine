package io.github.ak811.merkle.io;

import io.github.ak811.merkle.crypto.Hash32;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.SplittableRandom;

/**
 * Text files of transaction IDs: one 64-digit hex txid per line, in display order as shown by
 * block explorers and {@code bitcoin-cli}. Blank lines and lines starting with {@code #} are
 * ignored; anything else is rejected with its line number.
 */
public final class TxidFile {

    private TxidFile() {
    }

    public static TxidList read(Path file) throws IOException {
        byte[] leaves = new byte[1024 * Hash32.SIZE];
        int count = 0;
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.US_ASCII)) {
            String line;
            long lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                Hash32 txid;
                try {
                    txid = Hash32.fromDisplayHex(trimmed);
                } catch (IllegalArgumentException e) {
                    throw new IOException(file + ": line " + lineNumber + ": " + e.getMessage());
                }
                if ((long) (count + 1) * Hash32.SIZE > leaves.length) {
                    long grown = Math.min((long) leaves.length * 2, (long) (Integer.MAX_VALUE - 8) / Hash32.SIZE * Hash32.SIZE);
                    if (grown <= leaves.length) {
                        throw new IOException(file + ": too many txids to hold in memory");
                    }
                    leaves = Arrays.copyOf(leaves, (int) grown);
                }
                txid.copyInternalTo(leaves, count * Hash32.SIZE);
                count++;
            }
        }
        return new TxidList(Arrays.copyOf(leaves, count * Hash32.SIZE), count);
    }

    public static void write(Path file, TxidList txids) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(file, StandardCharsets.US_ASCII)) {
            for (int i = 0; i < txids.count(); i++) {
                writer.write(txids.get(i).toDisplayHex());
                writer.write('\n');
            }
        }
    }

    /** Returns {@code count} pseudo-random txids, reproducible for a given seed. */
    public static TxidList random(int count, long seed) {
        if (count < 0 || count > (Integer.MAX_VALUE - 8) / Hash32.SIZE) {
            throw new IllegalArgumentException("count out of range: " + count);
        }
        byte[] leaves = new byte[count * Hash32.SIZE];
        SplittableRandom random = new SplittableRandom(seed);
        for (int i = 0; i < leaves.length; i += 8) {
            long value = random.nextLong();
            for (int b = 0; b < 8; b++) {
                leaves[i + b] = (byte) (value >>> (8 * b));
            }
        }
        return new TxidList(leaves, count);
    }
}
