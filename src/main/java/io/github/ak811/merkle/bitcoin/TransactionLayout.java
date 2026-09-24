package io.github.ak811.merkle.bitcoin;

import java.util.List;

/**
 * Where one transaction's parts lie within the raw block bytes.
 *
 * <p>For a SegWit transaction, the serialization is
 * {@code version | marker 0x00 | flag 0x01 | inputs | outputs | witnesses | lock time}.
 * Its txid hashes the serialization <i>without</i> marker, flag, and witnesses, while its wtxid
 * hashes the full serialization. For a legacy transaction, both are the same.
 *
 * @param start           offset of the first byte
 * @param end             offset just past the last byte
 * @param segwit          whether the transaction uses the SegWit serialization
 * @param witnessStart    offset of the witness section (SegWit only)
 * @param witnessEnd      offset just past the witness section (SegWit only)
 * @param outputScripts   {@code [offset, length]} of each output script
 * @param firstInputWitness {@code [offset, length]} of each witness item of the first input
 */
public record TransactionLayout(int start, int end, boolean segwit, int witnessStart, int witnessEnd,
                                List<int[]> outputScripts, List<int[]> firstInputWitness) {

    public int length() {
        return end - start;
    }
}
