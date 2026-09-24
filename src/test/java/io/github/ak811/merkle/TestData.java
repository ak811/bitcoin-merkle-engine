package io.github.ak811.merkle;

import io.github.ak811.merkle.crypto.Hex;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Access to the test fixtures: real Bitcoin blocks and txid lists. */
public final class TestData {

    public static final String BLOCK_100000_ROOT = "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766";

    private TestData() {
    }

    public static Path resource(String name) {
        try {
            return Path.of(TestData.class.getResource("/" + name).toURI());
        } catch (URISyntaxException | NullPointerException e) {
            throw new IllegalStateException("missing test resource " + name, e);
        }
    }

    public static byte[] block(String name) {
        try {
            return Hex.decode(Files.readString(resource("blocks/" + name + ".hex")));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
