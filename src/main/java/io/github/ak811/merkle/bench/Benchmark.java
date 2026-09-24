package io.github.ak811.merkle.bench;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * A small measurement harness: untimed warm-up runs that let the JIT compiler optimize the hot
 * paths, followed by timed runs. Every run must produce an equal result.
 */
public final class Benchmark {

    /** Sorted timings and the common result of all runs. */
    public record Measurement<T>(T result, long[] nanos) {

        public Measurement {
            nanos = nanos.clone();
            Arrays.sort(nanos);
        }

        public long minNanos() {
            return nanos[0];
        }

        /** The median, taking the lower middle value for an even number of runs. */
        public long medianNanos() {
            return nanos[(nanos.length - 1) / 2];
        }

        @Override
        public long[] nanos() {
            return nanos.clone();
        }
    }

    private Benchmark() {
    }

    public static <T> Measurement<T> measure(Supplier<T> task, int warmup, int repeat) {
        Objects.requireNonNull(task, "task");
        if (warmup < 0 || repeat < 1) {
            throw new IllegalArgumentException("need warmup >= 0 and repeat >= 1");
        }
        T expected = null;
        for (int i = 0; i < warmup; i++) {
            expected = check(expected, task.get());
        }
        long[] nanos = new long[repeat];
        for (int i = 0; i < repeat; i++) {
            long start = System.nanoTime();
            T result = task.get();
            nanos[i] = System.nanoTime() - start;
            expected = check(expected, result);
        }
        return new Measurement<>(expected, nanos);
    }

    private static <T> T check(T expected, T actual) {
        if (expected != null && !expected.equals(actual)) {
            throw new IllegalStateException("runs returned different results: " + expected + " and " + actual);
        }
        return actual;
    }
}
