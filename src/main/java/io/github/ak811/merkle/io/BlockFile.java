package io.github.ak811.merkle.io;

import io.github.ak811.merkle.crypto.Hex;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads a serialized block from a file containing either raw bytes or hex text (for example,
 * the output of {@code bitcoin-cli getblock <hash> 0}). Hex is detected automatically.
 */
public final class BlockFile {

    private BlockFile() {
    }

    public static byte[] read(Path file) throws IOException {
        byte[] content = Files.readAllBytes(file);
        if (Hex.isHexText(content)) {
            try {
                return Hex.decode(new String(content, java.nio.charset.StandardCharsets.US_ASCII));
            } catch (IllegalArgumentException e) {
                throw new IOException(file + ": " + e.getMessage());
            }
        }
        return content;
    }
}
