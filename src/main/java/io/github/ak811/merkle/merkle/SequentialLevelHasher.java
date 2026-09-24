package io.github.ak811.merkle.merkle;

/** Hashes every level on the calling thread. */
public final class SequentialLevelHasher implements LevelHasher {

    @Override
    public boolean hashLevel(byte[] level, int count, byte[] out) {
        return MerkleLevels.hashParents(level, count, out, 0, MerkleLevels.parentCount(count));
    }

    @Override
    public int threads() {
        return 1;
    }
}
