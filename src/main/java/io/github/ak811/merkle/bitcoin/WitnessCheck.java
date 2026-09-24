package io.github.ak811.merkle.bitcoin;

/**
 * Outcome of checking a block's SegWit witness commitment (BIP 141).
 *
 * @param status the outcome
 * @param detail a human-readable explanation
 */
public record WitnessCheck(Status status, String detail) {

    public enum Status {
        /** No commitment and no SegWit transactions: nothing to check. */
        NOT_APPLICABLE,
        /** The commitment matches the witness Merkle root. */
        VALID,
        /** The commitment is missing, malformed, or does not match. */
        INVALID
    }

    public boolean passed() {
        return status != Status.INVALID;
    }
}
