package io.github.ak811.merkle.concurrent;

/** Thrown when a parallel loop cannot complete because a worker failed or was interrupted. */
public class ParallelExecutionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ParallelExecutionException(String message, Throwable cause) {
        super(message, cause);
    }
}
