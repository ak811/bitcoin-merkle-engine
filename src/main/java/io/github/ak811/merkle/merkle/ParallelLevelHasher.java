package io.github.ak811.merkle.merkle;

import io.github.ak811.merkle.concurrent.WorkerPool;

import java.util.Objects;

/**
 * Hashes each Merkle level in parallel.
 *
 * <p>All parents in a level are independent, so the level is split into contiguous ranges of
 * parents that threads compute concurrently, each writing only its own part of the output.
 * Levels are processed one after another, because each depends on the one below. Upper levels
 * with fewer than {@link #MIN_PARENTS_PER_CHUNK} parents per chunk run on the calling thread,
 * where dispatch would cost more than it saves.
 */
public final class ParallelLevelHasher implements LevelHasher {

    /** Parents per chunk below which a level is not split further. */
    public static final int MIN_PARENTS_PER_CHUNK = 1024;

    private final WorkerPool pool;
    private final boolean ownsPool;

    /** Creates a hasher with its own pool of {@code threads} threads. */
    public ParallelLevelHasher(int threads) {
        this(new WorkerPool(threads), true);
    }

    /** Creates a hasher that shares {@code pool}; the caller remains responsible for closing it. */
    public ParallelLevelHasher(WorkerPool pool) {
        this(pool, false);
    }

    private ParallelLevelHasher(WorkerPool pool, boolean ownsPool) {
        this.pool = Objects.requireNonNull(pool, "pool");
        this.ownsPool = ownsPool;
    }

    @Override
    public boolean hashLevel(byte[] level, int count, byte[] out) {
        return pool.anyMatch(MerkleLevels.parentCount(count), MIN_PARENTS_PER_CHUNK,
                (from, to) -> MerkleLevels.hashParents(level, count, out, from, to));
    }

    @Override
    public int threads() {
        return pool.threads();
    }

    @Override
    public void close() {
        if (ownsPool) {
            pool.close();
        }
    }
}
