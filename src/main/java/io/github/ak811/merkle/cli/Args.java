package io.github.ak811.merkle.cli;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Parsed command-line arguments: positional values, options with values, and boolean flags. */
final class Args {

    private final List<String> positionals = new ArrayList<>();
    private final Map<String, String> values = new HashMap<>();
    private final Set<String> flags = new HashSet<>();

    /**
     * Parses {@code args}, accepting only the given options.
     *
     * @throws UsageException for unknown options or missing values
     */
    static Args parse(String[] args, int from, Set<String> valueOptions, Set<String> flagOptions) {
        Args parsed = new Args();
        for (int i = from; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--")) {
                if (valueOptions.contains(arg)) {
                    if (i + 1 >= args.length) {
                        throw new UsageException(arg + " requires a value");
                    }
                    parsed.values.put(arg, args[++i]);
                } else if (flagOptions.contains(arg)) {
                    parsed.flags.add(arg);
                } else {
                    throw new UsageException("unknown option: " + arg);
                }
            } else {
                parsed.positionals.add(arg);
            }
        }
        return parsed;
    }

    String positional(int index, String name) {
        if (index >= positionals.size()) {
            throw new UsageException("missing " + name);
        }
        return positionals.get(index);
    }

    void requirePositionals(int max) {
        if (positionals.size() > max) {
            throw new UsageException("unexpected argument: " + positionals.get(max));
        }
    }

    boolean has(String option) {
        return flags.contains(option) || values.containsKey(option);
    }

    String value(String option) {
        String value = values.get(option);
        if (value == null) {
            throw new UsageException(option + " is required");
        }
        return value;
    }

    long longValue(String option, long defaultValue, long min, long max) {
        if (!values.containsKey(option)) {
            return defaultValue;
        }
        String text = values.get(option);
        long value;
        try {
            value = Long.parseLong(text);
        } catch (NumberFormatException e) {
            throw new UsageException(option + " expects an integer: " + text);
        }
        if (value < min || value > max) {
            throw new UsageException(option + " must be in [" + min + ", " + max + "]: " + text);
        }
        return value;
    }

    int intValue(String option, int defaultValue, int min, int max) {
        return (int) longValue(option, defaultValue, min, max);
    }

    /** Parses a comma-separated list of integers in {@code [min, max]}. */
    List<Integer> intList(String option, List<Integer> defaultValue, int min, int max) {
        if (!values.containsKey(option)) {
            return defaultValue;
        }
        List<Integer> result = new ArrayList<>();
        for (String part : values.get(option).split(",")) {
            try {
                int value = Integer.parseInt(part.trim());
                if (value < min || value > max) {
                    throw new UsageException(option + " values must be in [" + min + ", " + max + "]: " + part);
                }
                result.add(value);
            } catch (NumberFormatException e) {
                throw new UsageException(option + " expects comma-separated integers: " + values.get(option));
            }
        }
        return result;
    }

    /** Signals invalid command-line usage. */
    static final class UsageException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        UsageException(String message) {
            super(message);
        }
    }
}
