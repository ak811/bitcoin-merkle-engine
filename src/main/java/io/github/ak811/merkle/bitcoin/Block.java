package io.github.ak811.merkle.bitcoin;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A parsed Bitcoin block: the header and the location of every transaction in the raw bytes.
 *
 * <p>Parsing is strict: every CompactSize must be canonical, every length must fit in the data,
 * SegWit transactions must carry witness data, and the block must end exactly after its last
 * transaction.
 */
public final class Block {

    /** Upper bound on counts and lengths, well above Bitcoin's 4 MB block weight limit. */
    private static final long MAX_ITEMS = 32_000_000L;

    private final byte[] data;
    private final BlockHeader header;
    private final List<TransactionLayout> transactions;

    private Block(byte[] data, BlockHeader header, List<TransactionLayout> transactions) {
        this.data = data;
        this.header = header;
        this.transactions = transactions;
    }

    /** Parses a serialized block. The array is retained, not copied, and must not be modified. */
    public static Block parse(byte[] data) throws BlockFormatException {
        Objects.requireNonNull(data, "data");
        BlockHeader header = BlockHeader.parse(data);
        ByteReader reader = new ByteReader(data);
        reader.skip(BlockHeader.SIZE);
        int count = reader.compactSize(MAX_ITEMS, "transaction count");
        if (count == 0) {
            throw reader.error("a block must contain at least one transaction");
        }
        List<TransactionLayout> transactions = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            transactions.add(parseTransaction(reader, i == 0));
        }
        if (reader.remaining() != 0) {
            throw reader.error(reader.remaining() + " unexpected bytes after the last transaction");
        }
        return new Block(data, header, List.copyOf(transactions));
    }

    private static TransactionLayout parseTransaction(ByteReader reader, boolean first) throws BlockFormatException {
        int start = reader.position();
        reader.u32(); // version
        boolean segwit = false;
        if (reader.remaining() >= 2 && reader.peek(0) == 0x00) {
            if (reader.peek(1) != 0x01) {
                throw reader.error("unsupported transaction flags " + reader.peek(1));
            }
            segwit = true;
            reader.skip(2);
        }

        int inputs = reader.compactSize(MAX_ITEMS, "input count");
        if (inputs == 0) {
            throw reader.error("a transaction must have at least one input");
        }
        for (int i = 0; i < inputs; i++) {
            reader.skip(36); // previous output: txid and index
            reader.skip(reader.compactSize(MAX_ITEMS, "script length"));
            reader.skip(4); // sequence
        }

        int outputs = reader.compactSize(MAX_ITEMS, "output count");
        List<int[]> outputScripts = new ArrayList<>(first ? outputs : 0);
        for (int i = 0; i < outputs; i++) {
            reader.skip(8); // value
            int length = reader.compactSize(MAX_ITEMS, "script length");
            if (first) {
                outputScripts.add(new int[] {reader.position(), length});
            }
            reader.skip(length);
        }

        int witnessStart = reader.position();
        List<int[]> firstInputWitness = new ArrayList<>();
        if (segwit) {
            boolean anyWitness = false;
            for (int i = 0; i < inputs; i++) {
                int items = reader.compactSize(MAX_ITEMS, "witness item count");
                anyWitness |= items > 0;
                for (int j = 0; j < items; j++) {
                    int length = reader.compactSize(MAX_ITEMS, "witness item length");
                    if (first && i == 0) {
                        firstInputWitness.add(new int[] {reader.position(), length});
                    }
                    reader.skip(length);
                }
            }
            if (!anyWitness) {
                throw reader.error("SegWit transaction without witness data");
            }
        }
        int witnessEnd = reader.position();
        reader.u32(); // lock time
        return new TransactionLayout(start, reader.position(), segwit, witnessStart, witnessEnd,
                List.copyOf(outputScripts), List.copyOf(firstInputWitness));
    }

    public BlockHeader header() {
        return header;
    }

    public List<TransactionLayout> transactions() {
        return transactions;
    }

    public int transactionCount() {
        return transactions.size();
    }

    /** The raw block bytes. Callers must not modify the returned array. */
    byte[] data() {
        return data;
    }
}
