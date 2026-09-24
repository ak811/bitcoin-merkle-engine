package io.github.ak811.merkle.merkle;

import io.github.ak811.merkle.crypto.Hash32;
import io.github.ak811.merkle.crypto.Sha256d;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A Merkle inclusion proof: the sibling hashes on the path from one leaf to the root.
 *
 * <p>A verifier holding only the root, for example from a block header, can confirm that a
 * transaction is part of the tree using {@code log2(n)} hashes instead of all {@code n}
 * transactions. This is how Bitcoin's simplified payment verification (SPV) works.
 *
 * <p>Text format, one item per line: {@code index <leaf index>}, then each sibling hash in
 * display order, from the leaf level upward.
 *
 * @param index    position of the leaf among all leaves
 * @param siblings sibling hashes from the leaf level up to just below the root
 */
public record MerkleProof(int index, List<Hash32> siblings) {

    public MerkleProof {
        if (index < 0) {
            throw new IllegalArgumentException("index must be non-negative: " + index);
        }
        siblings = List.copyOf(siblings);
        if (siblings.size() < 31 && index >= (1 << siblings.size())) {
            throw new IllegalArgumentException("index " + index + " needs more than " + siblings.size() + " levels");
        }
    }

    /** Recomputes the root implied by this proof for {@code leaf}. */
    public Hash32 rootFor(Hash32 leaf) {
        Objects.requireNonNull(leaf, "leaf");
        byte[] pair = new byte[2 * Hash32.SIZE];
        byte[] current = leaf.internalBytes();
        int position = index;
        for (Hash32 sibling : siblings) {
            if ((position & 1) == 0) {
                System.arraycopy(current, 0, pair, 0, Hash32.SIZE);
                sibling.copyInternalTo(pair, Hash32.SIZE);
            } else {
                sibling.copyInternalTo(pair, 0);
                System.arraycopy(current, 0, pair, Hash32.SIZE, Hash32.SIZE);
            }
            Sha256d.hashPair(pair, 0, Hash32.SIZE, current, 0);
            position >>>= 1;
        }
        return Hash32.fromInternal(current);
    }

    /** Returns true if this proof shows that {@code leaf} is included under {@code root}. */
    public boolean verify(Hash32 leaf, Hash32 root) {
        return rootFor(leaf).equals(Objects.requireNonNull(root, "root"));
    }

    /** Serializes the proof in its text format. */
    public String toText() {
        StringBuilder text = new StringBuilder("index ").append(index).append('\n');
        for (Hash32 sibling : siblings) {
            text.append(sibling.toDisplayHex()).append('\n');
        }
        return text.toString();
    }

    /**
     * Parses the text format. Blank lines and lines starting with {@code #} are ignored.
     *
     * @throws IllegalArgumentException if the text is malformed
     */
    public static MerkleProof parse(String text) {
        Integer index = null;
        List<Hash32> siblings = new ArrayList<>();
        String[] lines = text.split("\\R");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            try {
                if (index == null) {
                    if (!line.startsWith("index ")) {
                        throw new IllegalArgumentException("expected 'index <n>'");
                    }
                    index = Integer.parseInt(line.substring("index ".length()).trim());
                } else {
                    siblings.add(Hash32.fromDisplayHex(line));
                }
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("proof line " + (i + 1) + ": " + e.getMessage(), e);
            }
        }
        if (index == null) {
            throw new IllegalArgumentException("proof is empty");
        }
        return new MerkleProof(index, siblings);
    }
}
