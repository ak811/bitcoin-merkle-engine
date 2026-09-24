package io.github.ak811.merkle.bitcoin;

/** Bounds-checked little-endian reader over a byte array, following Bitcoin's serialization rules. */
final class ByteReader {

    private final byte[] data;
    private final int end;
    private int position;

    ByteReader(byte[] data) {
        this.data = data;
        this.end = data.length;
    }

    int position() {
        return position;
    }

    int remaining() {
        return end - position;
    }

    int peek(int ahead) throws BlockFormatException {
        require(ahead + 1);
        return data[position + ahead] & 0xff;
    }

    int u8() throws BlockFormatException {
        require(1);
        return data[position++] & 0xff;
    }

    long u32() throws BlockFormatException {
        require(4);
        long value = (data[position] & 0xffL)
                | (data[position + 1] & 0xffL) << 8
                | (data[position + 2] & 0xffL) << 16
                | (data[position + 3] & 0xffL) << 24;
        position += 4;
        return value;
    }

    long u64() throws BlockFormatException {
        long low = u32();
        long high = u32();
        return low | high << 32;
    }

    void skip(long count) throws BlockFormatException {
        if (count < 0 || count > remaining()) {
            throw error("need " + count + " bytes, " + remaining() + " remain");
        }
        position += (int) count;
    }

    /**
     * Reads a CompactSize integer, rejecting non-canonical encodings as Bitcoin Core does, and
     * requires it to be at most {@code max}.
     */
    int compactSize(long max, String what) throws BlockFormatException {
        int first = u8();
        long value;
        if (first < 0xfd) {
            value = first;
        } else if (first == 0xfd) {
            require(2);
            value = (data[position] & 0xffL) | (data[position + 1] & 0xffL) << 8;
            position += 2;
            if (value < 0xfd) {
                throw error("non-canonical CompactSize for " + what);
            }
        } else if (first == 0xfe) {
            value = u32();
            if (value < 0x10000L) {
                throw error("non-canonical CompactSize for " + what);
            }
        } else {
            value = u64();
            if (value >= 0 && value < 0x100000000L) {
                throw error("non-canonical CompactSize for " + what);
            }
        }
        if (value < 0 || value > max) {
            throw error(what + " " + Long.toUnsignedString(value) + " exceeds " + max);
        }
        return (int) value;
    }

    BlockFormatException error(String message) {
        return new BlockFormatException("at byte " + position + ": " + message);
    }

    private void require(int count) throws BlockFormatException {
        if (count > remaining()) {
            throw error("unexpected end of data (need " + count + " bytes, " + remaining() + " remain)");
        }
    }
}
