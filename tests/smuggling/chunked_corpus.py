"""Chunked-body cases (task #3, docs/framing.md section 7).

Each case: (id, body bytes, max body, outcome, consumed or rule tag, body bytes counted, source).
outcome is "done" (the message ends; `consumed` bytes belong to it), "more" (valid so far) or "refuse" (rule tag).
"""

RFC = "RFC 9112 7.1"
KETTLE = "Kettle 2019, 'HTTP Desync Attacks: Request Smuggling Reborn'"
LLHTTP = "llhttp test/request (nodejs/llhttp), the malformed-request cases"

CASES = [
    ("simple", b"5\r\nhello\r\n0\r\n\r\n", 100, "done", 15, 5, RFC),
    ("empty-body", b"0\r\n\r\n", 100, "done", 5, 0, RFC),
    ("two-chunks", b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", 100, "done", 20, 5, RFC),
    ("hex-uppercase", b"A\r\n0123456789\r\n0\r\n\r\n", 100, "done", 20, 10, RFC + " (chunk-size is HEXDIG)"),
    ("hex-lowercase", b"a\r\n0123456789\r\n0\r\n\r\n", 100, "done", 20, 10, RFC),
    ("leading-zeros", b"0005\r\nhello\r\n0\r\n\r\n", 100, "done", 18, 5, RFC),
    ("body-with-crlf-inside", b"4\r\n\r\n\r\n\r\n0\r\n\r\n", 100, "done", 14, 4, RFC + " (data is opaque)"),
    ("data-looks-like-last-chunk", b"7\r\n0\r\n\r\nxx\r\n0\r\n\r\n", 100, "done", 17, 7, "a smuggled terminator inside data must not end the message"),
    ("next-request-not-consumed", b"0\r\n\r\nGET / HTTP/1.1\r\n\r\n", 100, "done", 5, 0, "pipelining: bytes after the message belong to the next one"),
    ("incomplete-size", b"5", 100, "more", 1, 0, "arrives in pieces"),
    ("incomplete-data", b"5\r\nhel", 100, "more", 6, 3, "arrives in pieces"),
    ("incomplete-final", b"5\r\nhello\r\n0\r\n", 100, "more", 13, 5, "arrives in pieces"),
    ("empty-input", b"", 100, "more", 0, 0, "nothing yet"),
    # --- refusals
    ("extension", b"5;name=value\r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-extension", None, RFC + " (ignorable; refused: a lever for smuggling)"),
    ("extension-empty", b"5;\r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-extension", None, "same"),
    ("extension-on-last-chunk", b"5\r\nhello\r\n0;x\r\n\r\n", 100, "refuse", "framing.chunk-extension", None, "same"),
    ("space-after-size", b"5 \r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-size", None, "BWS around the size is refused"),
    ("space-before-size", b" 5\r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-size", None, "same"),
    ("tab-after-size", b"5\t\r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-size", None, "same"),
    ("no-digits", b"\r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-size", None, RFC),
    ("non-hex", b"g\r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-size", None, RFC),
    ("negative", b"-5\r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-size", None, RFC),
    ("hex-prefix", b"0x5\r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-size", None, RFC),
    ("size-overflow", b"FFFFFFFFFFFFFFFFF\r\n", 100, "refuse", "framing.chunk-size", None, "integer overflow in the size; " + KETTLE),
    ("nine-digits", b"000000001\r\nx\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-size", None, "more than 8 hex digits is refused even if the value is small"),
    ("bare-lf-size", b"5\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-size", None, "RFC 9112 2.2; a bare LF is not the end of the size line"),
    ("size-cr-then-junk", b"5\rXhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-framing", None, "CR must be followed by LF"),
    ("data-longer-than-size", b"3\r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-framing", None, "the size lies: the data is followed by the wrong bytes"),
    ("data-shorter-than-size", b"7\r\nhello\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-framing", None, "the size lies the other way (it swallows the terminator)"),
    ("missing-crlf-after-data", b"5\r\nhello0\r\n\r\n", 100, "refuse", "framing.chunk-framing", None, RFC),
    ("wrong-byte-then-lf-after-data", b"5\r\nhelloX\n0\r\n\r\n", 100, "refuse", "framing.chunk-framing", None, "a mutant that skips the CR check after data accepted this: the byte before LF must be CR"),
    ("lf-only-after-data", b"5\r\nhello\n0\r\n\r\n", 100, "refuse", "framing.chunk-framing", None, "RFC 9112 2.2"),
    ("trailer", b"0\r\nX-Trailer: 1\r\n\r\n", 100, "refuse", "framing.trailers", None, RFC + " 7.1.2 (a recipient MAY discard; refused)"),
    ("last-chunk-lf-only", b"0\r\n\n", 100, "refuse", "framing.trailers", None, "a bare LF in place of the final CRLF"),
    ("last-chunk-cr-junk", b"0\r\n\rX", 100, "refuse", "framing.chunk-framing", None, "CR must be followed by LF"),
    ("over-body-limit", b"6\r\nabcdef\r\n0\r\n\r\n", 5, "refuse", "limit.body", None, "design section 4 (limit.body), refused before the data is read"),
    ("over-limit-across-chunks", b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n", 5, "refuse", "limit.body", None, "the total, not each chunk"),
    ("exactly-at-limit", b"5\r\nhello\r\n0\r\n\r\n", 5, "done", 15, 5, "the limit is inclusive"),
    ("huge-declared-size", b"FFFFFFFF\r\n", 1000000, "refuse", "limit.body", None, "a declared 4 GiB chunk is refused at the size line, not buffered"),
    # --- llhttp's malformed chunked bodies (test/request/transfer-encoding.md), byte for byte
    ("llhttp-ext-no-semicolon", b"2 erfrferferf\r\naa\r\n0 rrrr\r\n\r\n", 100, "refuse", "framing.chunk-size", None, LLHTTP + ": spaces where the size line ends"),
    ("llhttp-ext-only-semicolon", b"2;\r\naa\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-extension", None, LLHTTP + ": a chunk extension is refused, empty or not"),
    ("llhttp-size-not-crlf", b"5\r\r;ABCD\r\n34\r\nE\r\n0\r\n\r\n", 100, "refuse", "framing.chunk-framing", None, LLHTTP + ": a bare CR after the size"),
    ("llhttp-data-not-crlf", b"5\r\nABCDE0\r\n\r\n", 100, "refuse", "framing.chunk-framing", None, LLHTTP + ": the data runs past its size into the terminator"),
]
