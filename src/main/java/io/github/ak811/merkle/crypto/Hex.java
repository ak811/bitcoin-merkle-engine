package io.github.ak811.merkle.crypto;

/** Hexadecimal encoding and decoding. */
public final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    /** Encodes {@code bytes} as lowercase hexadecimal. */
    public static String encode(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[2 * i] = DIGITS[(bytes[i] >> 4) & 0xf];
            out[2 * i + 1] = DIGITS[bytes[i] & 0xf];
        }
        return new String(out);
    }

    /**
     * Decodes hexadecimal text, ignoring whitespace.
     *
     * @throws IllegalArgumentException if the text contains a non-hex character or an odd number of digits
     */
    public static byte[] decode(CharSequence text) {
        byte[] out = new byte[text.length() / 2];
        int size = 0;
        int high = -1;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isWhitespace(c)) {
                continue;
            }
            int digit = Character.digit(c, 16);
            if (digit < 0) {
                throw new IllegalArgumentException("invalid hex character '" + c + "' at position " + i);
            }
            if (high < 0) {
                high = digit;
            } else {
                out[size++] = (byte) ((high << 4) | digit);
                high = -1;
            }
        }
        if (high >= 0) {
            throw new IllegalArgumentException("hex text has an odd number of digits");
        }
        return size == out.length ? out : java.util.Arrays.copyOf(out, size);
    }

    /** Returns true if {@code text} consists only of hex digits and whitespace, with at least one digit. */
    public static boolean isHexText(byte[] text) {
        boolean digits = false;
        for (byte b : text) {
            if (Character.digit(b, 16) >= 0) {
                digits = true;
            } else if (b != ' ' && b != '\t' && b != '\r' && b != '\n') {
                return false;
            }
        }
        return digits;
    }
}
