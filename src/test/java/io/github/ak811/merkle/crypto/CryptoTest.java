package io.github.ak811.merkle.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoTest {

    @Test
    void doubleSha256MatchesKnownVectors() {
        assertEquals("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
                Sha256d.hash(new byte[0]).toInternalHex());
        assertEquals("4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358",
                Sha256d.hash("abc".getBytes(StandardCharsets.US_ASCII)).toInternalHex());
    }

    @Test
    void rangeHashingEqualsHashingTheConcatenation() {
        byte[] data = "0123456789abcdefghij".getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[32];
        Sha256d.hashRanges(data, 0, 4, 6, 5, 15, 5, out, 0);
        byte[] joined = "0123" .concat("6789a").concat("fghij").getBytes(StandardCharsets.US_ASCII);
        assertEquals(Sha256d.hash(joined), Hash32.fromInternal(out));
    }

    @Test
    void pairHashingEqualsHashingSixtyFourBytes() {
        byte[] data = new byte[64];
        for (int i = 0; i < 64; i++) {
            data[i] = (byte) i;
        }
        byte[] out = new byte[32];
        Sha256d.hashPair(data, 0, 32, out, 0);
        assertEquals(Sha256d.hash(data), Hash32.fromInternal(out));
    }

    @Test
    void displayOrderIsReversedInternalOrder() {
        Hash32 hash = Hash32.fromDisplayHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        assertEquals("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000", hash.toInternalHex());
        assertEquals("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", hash.toDisplayHex());
        assertEquals(hash, Hash32.fromInternal(hash.internalBytes()));
        assertNotEquals(hash, Hash32.ZERO);
    }

    @Test
    void hexRoundTripsAndRejectsBadInput() {
        byte[] bytes = {0, 1, (byte) 0xab, (byte) 0xff};
        assertEquals("0001abff", Hex.encode(bytes));
        assertArrayEquals(bytes, Hex.decode("00 01\nAB ff"));
        assertThrows(IllegalArgumentException.class, () -> Hex.decode("abc"));
        assertThrows(IllegalArgumentException.class, () -> Hex.decode("zz"));
        assertThrows(IllegalArgumentException.class, () -> Hash32.fromDisplayHex("abcd"));
        assertTrue(Hex.isHexText("ab cd\n".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(Hex.isHexText(new byte[] {1, 2, 3}));
        assertFalse(Hex.isHexText("   ".getBytes(StandardCharsets.US_ASCII)));
    }
}
