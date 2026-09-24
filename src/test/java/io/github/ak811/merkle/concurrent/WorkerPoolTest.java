package io.github.ak811.merkle.concurrent;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicIntegerArray;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WorkerPoolTest {

    @Test
    void visitsEveryIndexExactlyOnce() {
        for (int threads : new int[] {1, 2, 3, 8}) {
            try (WorkerPool pool = new WorkerPool(threads)) {
                for (int n : new int[] {0, 1, 5, 1000, 100_003}) {
                    AtomicIntegerArray visits = new AtomicIntegerArray(n);
                    pool.anyMatch(n, 7, (from, to) -> {
                        for (int i = from; i < to; i++) {
                            visits.incrementAndGet(i);
                        }
                        return false;
                    });
                    for (int i = 0; i < n; i++) {
                        assertEquals(1, visits.get(i), "index " + i + ", n=" + n + ", threads=" + threads);
                    }
                }
            }
        }
    }

    @Test
    void combinesChunkResultsWithOr() {
        try (WorkerPool pool = new WorkerPool(4)) {
            assertFalse(pool.anyMatch(10_000, 10, (from, to) -> false));
            assertTrue(pool.anyMatch(10_000, 10, (from, to) -> from <= 9_999 && 9_999 < to));
        }
    }

    @Test
    void propagatesFailures() {
        try (WorkerPool pool = new WorkerPool(4)) {
            assertThrows(IllegalStateException.class, () -> pool.anyMatch(10_000, 10, (from, to) -> {
                throw new IllegalStateException("boom");
            }));
            assertThrows(ParallelExecutionException.class, () -> pool.anyMatch(10_000, 10, (from, to) -> {
                throw new IOException("checked boom");
            }));
        }
    }

    @Test
    void rejectsInvalidConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> new WorkerPool(0));
        assertThrows(IllegalArgumentException.class, () -> new WorkerPool(WorkerPool.MAX_THREADS + 1));
        try (WorkerPool pool = new WorkerPool(2)) {
            assertThrows(IllegalArgumentException.class, () -> pool.anyMatch(-1, 1, (a, b) -> false));
        }
    }
}
