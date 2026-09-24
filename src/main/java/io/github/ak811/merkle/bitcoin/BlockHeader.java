package io.github.ak811.merkle.bitcoin;

import io.github.ak811.merkle.crypto.Hash32;
import io.github.ak811.merkle.crypto.Sha256d;

import java.math.BigInteger;
import java.util.Optional;

/**
 * The 80-byte Bitcoin block header.
 *
 * @param version    block version
 * @param prevBlock  hash of the previous block
 * @param merkleRoot Merkle root the block commits to
 * @param time       Unix timestamp
 * @param bits       compact encoding of the proof-of-work target
 * @param nonce      proof-of-work nonce
 * @param hash       double SHA-256 of the header, which identifies the block
 */
public record BlockHeader(long version, Hash32 prevBlock, Hash32 merkleRoot, long time, long bits,
                          long nonce, Hash32 hash) {

    public static final int SIZE = 80;

    static BlockHeader parse(byte[] data) throws BlockFormatException {
        if (data.length < SIZE) {
            throw new BlockFormatException("a block header is " + SIZE + " bytes, got " + data.length);
        }
        ByteReader reader = new ByteReader(data);
        long version = reader.u32();
        Hash32 prev = Hash32.fromInternal(data, 4);
        Hash32 merkle = Hash32.fromInternal(data, 36);
        reader.skip(64);
        long time = reader.u32();
        long bits = reader.u32();
        long nonce = reader.u32();
        return new BlockHeader(version, prev, merkle, time, bits, nonce, Sha256d.hash(data, 0, SIZE));
    }

    /**
     * Decodes {@code bits} into the target the block hash must not exceed, or empty if the
     * encoding is negative, zero, or overflows 256 bits (all invalid in Bitcoin Core).
     */
    public Optional<BigInteger> target() {
        int exponent = (int) (bits >>> 24);
        long mantissa = bits & 0x007fffffL;
        boolean negative = mantissa != 0 && (bits & 0x00800000L) != 0;
        boolean overflow = mantissa != 0 && (exponent > 34
                || (mantissa > 0xff && exponent > 33)
                || (mantissa > 0xffff && exponent > 32));
        BigInteger target = exponent <= 3
                ? BigInteger.valueOf(mantissa >>> (8 * (3 - exponent)))
                : BigInteger.valueOf(mantissa).shiftLeft(8 * (exponent - 3));
        if (negative || overflow || target.signum() == 0) {
            return Optional.empty();
        }
        return Optional.of(target);
    }

    /**
     * Returns true if the block hash, read as a 256-bit number, does not exceed the target encoded
     * in {@code bits}. This checks that the header carries valid work for its own stated target;
     * whether that target is correct for the block's height requires the preceding chain.
     */
    public boolean hasValidProofOfWork() {
        return target().map(t -> new BigInteger(1, reverse(hash.internalBytes())).compareTo(t) <= 0)
                .orElse(false);
    }

    private static byte[] reverse(byte[] bytes) {
        for (int i = 0, j = bytes.length - 1; i < j; i++, j--) {
            byte tmp = bytes[i];
            bytes[i] = bytes[j];
            bytes[j] = tmp;
        }
        return bytes;
    }
}
