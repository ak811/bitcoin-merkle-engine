package io.github.ak811.merkle.concurrent;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A fixed pool of worker threads for data-parallel loops over an index range.
 *
 * <p>{@link #anyMatch} splits {@code [0, n)} into contiguous chunks, runs them on the pool, and
 * waits for all of them. Each chunk writes only to its own part of the output, so the loops
 * need no locks. Ranges too small to benefit from parallelism run on the calling thread.
 * The pool is created once and reused, so thread start-up is not paid per call.
 */
public final class WorkerPool implements AutoCloseable {

    /** Maximum supported thread count. */
    public static final int MAX_THREADS = 1024;

    /** Chunks per thread; more than one lets faster threads pick up extra work. */
    private static final int CHUNKS_PER_THREAD = 4;

    /** Work over a half-open index range; returns a flag that is OR-ed across chunks. */
    @FunctionalInterface
    public interface RangeTask {
        boolean run(int from, int to) throws Exception;
    }

    private final int threads;
    private final ExecutorService executor;

    public WorkerPool(int threads) {
        if (threads < 1 || threads > MAX_THREADS) {
            throw new IllegalArgumentException("threads must be in [1, " + MAX_THREADS + "]: " + threads);
        }
        this.threads = threads;
        this.executor = threads == 1 ? null : Executors.newFixedThreadPool(threads, daemonThreads());
    }

    public int threads() {
        return threads;
    }

    /**
     * Runs {@code task} over {@code [0, n)} and returns true if any chunk returned true.
     *
     * @param minChunk smallest range worth handing to another thread
     * @throws ParallelExecutionException if any chunk throws
     */
    public boolean anyMatch(int n, int minChunk, RangeTask task) {
        if (n < 0 || minChunk < 1) {
            throw new IllegalArgumentException("invalid range size " + n + " or chunk size " + minChunk);
        }
        int chunks = executor == null ? 1
                : (int) Math.min((long) threads * CHUNKS_PER_THREAD, Math.max(1, n / minChunk));
        if (chunks <= 1) {
            return runInline(task, 0, n);
        }
        List<Callable<Boolean>> tasks = new ArrayList<>(chunks);
        for (int c = 0; c < chunks; c++) {
            int from = (int) ((long) n * c / chunks);
            int to = (int) ((long) n * (c + 1) / chunks);
            tasks.add(() -> task.run(from, to));
        }
        try {
            boolean any = false;
            for (Future<Boolean> future : executor.invokeAll(tasks)) {
                any |= future.get();
            }
            return any;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ParallelExecutionException("interrupted while waiting for worker threads", e);
        } catch (ExecutionException e) {
            // Surface unchecked exceptions unchanged, exactly as the inline path does.
            if (e.getCause() instanceof RuntimeException runtime) {
                throw runtime;
            }
            throw new ParallelExecutionException("worker thread failed: " + e.getCause().getMessage(), e.getCause());
        }
    }

    private static boolean runInline(RangeTask task, int from, int to) {
        try {
            return task.run(from, to);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new ParallelExecutionException(e.getMessage(), e);
        }
    }

    @Override
    public void close() {
        if (executor != null) {
            executor.shutdownNow();
            try {
                executor.awaitTermination(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static java.util.concurrent.ThreadFactory daemonThreads() {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, "merkle-worker-" + counter.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        };
    }
}
