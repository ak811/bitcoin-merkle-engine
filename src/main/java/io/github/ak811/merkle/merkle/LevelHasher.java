package io.github.ak811.merkle.merkle;

/** Computes one Merkle level from the level below it; implementations differ in parallelism. */
public interface LevelHasher extends AutoCloseable {

    /**
     * Writes the {@link MerkleLevels#parentCount(int)} parents of {@code level} into {@code out}.
     *
     * @return true if the level is mutated (see {@link MerkleLevels})
     */
    boolean hashLevel(byte[] level, int count, byte[] out);

    /** Number of threads this hasher uses. */
    int threads();

    @Override
    default void close() {
    }
}
