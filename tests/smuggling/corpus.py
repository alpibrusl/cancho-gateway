"""The request-smuggling and ambiguity corpus (task #3, docs/framing.md).

Each case: (id, request bytes, headers allowed, what the gateway must do, status, source).
`must` is "accept" or "refuse"; `status` is the HTTP status the gateway answers when it refuses (None if accepted).
Sources are the sections that make the case a case. NOT yet consulted: the llhttp and nginx test suites named in
issue #3; cases from them are added when they are read, and listed here by their file.
"""

H = b"Host: a\r\n"
RFC9112 = "RFC 9112"
KETTLE = "Kettle 2019, 'HTTP Desync Attacks: Request Smuggling Reborn' (PortSwigger)"
LLHTTP = "llhttp test/request (nodejs/llhttp): the malformed-request fixtures, decoded the way its own runner decodes them"

CASES = [
    # --- must be accepted: the baseline a proxy exists for
    ("get", b"GET / HTTP/1.1\r\n" + H + b"\r\n", 16, "accept", None, RFC9112 + " 3"),
    ("post-content-length", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 5\r\n\r\nhello", 16, "accept", None, RFC9112 + " 6.2"),
    ("post-chunked", b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 16, "accept", None, RFC9112 + " 6.1"),
    ("http-1.0", b"GET / HTTP/1.0\r\n\r\n", 16, "accept", None, RFC9112 + " 2.3 (a proxy still serves 1.0 clients)"),
    ("content-length-trailing-ows", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 5 \r\n\r\nhello", 16, "accept", None, RFC9112 + " 5 (OWS)"),
    ("te-tab-after-colon", b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding:\tchunked\r\n\r\n0\r\n\r\n", 16, "accept", None, RFC9112 + " 5 (HTAB is OWS; legal, and a Kettle obfuscation if a peer disagrees)"),
    ("connection-close", b"GET / HTTP/1.1\r\n" + H + b"Connection: close\r\n\r\n", 16, "accept", None, RFC9112 + " 9.6"),
    # --- two body lengths
    ("cl-and-te", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 16, "refuse", 400, RFC9112 + " 6.3 item 3; " + KETTLE + " (CL.TE, TE.CL)"),
    ("te-then-cl", b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n", 16, "refuse", 400, RFC9112 + " 6.3 item 3"),
    ("cl-and-te-identity", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 5\r\nTransfer-Encoding: identity\r\n\r\nhello", 16, "refuse", 400, RFC9112 + " 6.3"),
    ("duplicate-cl-differ", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello!", 16, "refuse", 400, RFC9112 + " 6.3 item 5"),
    ("duplicate-cl-same", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello", 16, "refuse", 400, "refused though RFC 9112 6.3 allows folding identical values: one framing, no tolerance (design section 6)"),
    ("cl-list", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 5, 5\r\n\r\nhello", 16, "refuse", 400, RFC9112 + " 6.3 item 5"),
    ("cl-letters", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: abc\r\n\r\n", 16, "refuse", 400, RFC9112 + " 6.2 (1*DIGIT)"),
    ("cl-plus", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: +5\r\n\r\nhello", 16, "refuse", 400, RFC9112 + " 6.2"),
    ("cl-minus", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: -1\r\n\r\n", 16, "refuse", 400, RFC9112 + " 6.2"),
    ("cl-hex", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 0x5\r\n\r\nhello", 16, "refuse", 400, RFC9112 + " 6.2"),
    ("cl-overflow", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 99999999999999999999\r\n\r\n", 16, "refuse", 400, "integer overflow; " + RFC9112 + " 6.2"),
    ("cl-empty", b"POST / HTTP/1.1\r\n" + H + b"Content-Length:\r\n\r\n", 16, "refuse", 400, RFC9112 + " 6.2"),
    # --- Transfer-Encoding obfuscation
    ("te-xchunked", b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding: xchunked\r\n\r\n0\r\n\r\n", 16, "refuse", 501, KETTLE + " (obfuscated TE); " + RFC9112 + " 6.1"),
    ("te-gzip-only", b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding: gzip\r\n\r\n", 16, "refuse", 501, RFC9112 + " 6.3 item 4"),
    ("te-gzip-chunked", b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", 16, "refuse", 501, "design section 6: TE other than chunked is refused"),
    ("te-chunked-twice", b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 16, "refuse", 400, RFC9112 + " 6.1; " + KETTLE),
    ("te-chunked-then-identity", b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n", 16, "refuse", 400, KETTLE),
    ("te-space-before-colon", b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding : chunked\r\n\r\n0\r\n\r\n", 16, "refuse", 400, RFC9112 + " 5.1; " + KETTLE),
    ("te-leading-space-line", b"POST / HTTP/1.1\r\n" + H + b" Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 16, "refuse", 400, RFC9112 + " 5.2 (obs-fold); " + KETTLE),
    ("te-in-obs-fold", b"POST / HTTP/1.1\r\n" + H + b"X: X\r\n Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 16, "refuse", 400, RFC9112 + " 5.2; " + KETTLE),
    ("te-chunked-capitalised", b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding: Chunked\r\n\r\n0\r\n\r\n", 16, "accept", None, RFC9112 + " 7 (transfer-coding names are case-insensitive)"),
    # --- line endings and control bytes
    ("bare-lf", b"GET / HTTP/1.1\nHost: a\n\n", 16, "refuse", 400, RFC9112 + " 2.2 (a recipient MAY accept; the gateway does not)"),
    ("bare-lf-header", b"GET / HTTP/1.1\r\nHost: a\nX: y\r\n\r\n", 16, "refuse", 400, RFC9112 + " 2.2"),
    ("bare-cr-value", b"GET / HTTP/1.1\r\nHost: a\r\nX: y\rz\r\n\r\n", 16, "refuse", 400, RFC9112 + " 2.2 (a bare CR is replaced by SP or refused)"),
    ("nul-in-value", b"GET / HTTP/1.1\r\nHost: a\r\nX: y\x00z\r\n\r\n", 16, "refuse", 400, "RFC 9110 5.5 (field values: no control bytes)"),
    ("nul-in-name", b"GET / HTTP/1.1\r\nHost: a\r\nX\x00Y: z\r\n\r\n", 16, "refuse", 400, "RFC 9110 5.1 (token)"),
    ("del-in-value", b"GET / HTTP/1.1\r\nHost: a\r\nX: y\x7fz\r\n\r\n", 16, "refuse", 400, "RFC 9110 5.5"),
    ("leading-crlf", b"\r\nGET / HTTP/1.1\r\n" + H + b"\r\n", 16, "refuse", 400, RFC9112 + " 2.2 (a recipient SHOULD ignore it; the gateway refuses)"),
    # --- header syntax
    ("space-before-colon", b"GET / HTTP/1.1\r\nHost : a\r\n\r\n", 16, "refuse", 400, RFC9112 + " 5.1"),
    ("space-in-name", b"GET / HTTP/1.1\r\nHo st: a\r\n\r\n", 16, "refuse", 400, "RFC 9110 5.1 (token)"),
    ("at-in-name", b"GET / HTTP/1.1\r\nHo@st: a\r\n\r\n", 16, "refuse", 400, "RFC 9110 5.1"),
    ("empty-name", b"GET / HTTP/1.1\r\n" + H + b": x\r\n\r\n", 16, "refuse", 400, "RFC 9110 5.1"),
    ("no-colon", b"GET / HTTP/1.1\r\n" + H + b"Junk\r\n\r\n", 16, "refuse", 400, RFC9112 + " 5"),
    ("missing-host", b"GET / HTTP/1.1\r\n\r\n", 16, "refuse", 400, RFC9112 + " 3.2"),
    ("duplicate-host", b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 16, "refuse", 400, "RFC 9110 7.2; host confusion"),
    ("too-many-headers", b"GET / HTTP/1.1\r\n" + H + b"A: 1\r\nB: 2\r\n\r\n", 2, "refuse", 431, "design section 4 (limit.headers)"),
    # --- request line
    ("absolute-form", b"GET http://evil.example/ HTTP/1.1\r\n" + H + b"\r\n", 16, "refuse", 400, RFC9112 + " 3.2.2; design section 6"),
    ("connect", b"CONNECT a:443 HTTP/1.1\r\n" + H + b"\r\n", 16, "refuse", 501, RFC9112 + " 3.2.3; design section 6"),
    ("asterisk-form-get", b"GET * HTTP/1.1\r\n" + H + b"\r\n", 16, "refuse", 400, RFC9112 + " 3.2.4 (only OPTIONS)"),
    ("http-0.9", b"GET /\r\n\r\n", 16, "refuse", 400, "no request-line version"),
    ("http-2.0", b"GET / HTTP/2.0\r\n" + H + b"\r\n", 16, "refuse", 505, RFC9112 + " 2.3"),
    ("http-1.2", b"GET / HTTP/1.2\r\n" + H + b"\r\n", 16, "refuse", 505, "no minor version above 1.1 is spoken"),
    ("double-space", b"GET  / HTTP/1.1\r\n" + H + b"\r\n", 16, "refuse", 400, RFC9112 + " 3 (single SP)"),
    ("space-in-target", b"GET /a b HTTP/1.1\r\n" + H + b"\r\n", 16, "refuse", 400, RFC9112 + " 3.2"),
    ("control-in-target", b"GET /a\x01b HTTP/1.1\r\n" + H + b"\r\n", 16, "refuse", 400, "RFC 3986 2"),
    ("high-bytes-in-target", b"GET /\xff HTTP/1.1\r\n" + H + b"\r\n", 16, "refuse", 400, "RFC 3986 2 (non-ASCII is percent-encoded)"),
    ("tab-after-method", b"GET\t/ HTTP/1.1\r\n" + H + b"\r\n", 16, "refuse", 400, RFC9112 + " 3 (a single SP)"),
    ("lowercase-version", b"GET / http/1.1\r\n" + H + b"\r\n", 16, "refuse", 400, RFC9112 + " 2.3 (HTTP-name is case-sensitive)"),
    # --- sizes and incomplete input (framing.head_limit() is 16384)
    ("incomplete-no-blank-line", b"GET / HTTP/1.1\r\nHost: a\r\n", 16, "more", None, "a head arrives in pieces"),
    ("incomplete-empty", b"", 16, "more", None, "nothing yet"),
    ("head-at-limit", b"GET / HTTP/1.1\r\n" + H + b"X: " + b"a" * (16384 - 16 - len(H) - 3 - 2 - 2) + b"\r\n\r\n", 16, "accept", None, "design section 4 (limit.head): exactly 16384 bytes"),
    ("head-over-limit", b"GET / HTTP/1.1\r\n" + H + b"X: " + b"a" * (16384 - 16 - len(H) - 3 - 2 - 2 + 1) + b"\r\n\r\n", 16, "refuse", 431, "design section 4 (limit.head): 16385 bytes"),
    ("no-blank-line-over-limit", b"GET / HTTP/1.1\r\n" + H + b"X: " + b"a" * 16400, 16, "refuse", 431, "design section 4: a peer must not make the gateway buffer without bound"),
    # --- llhttp's malformed requests (nodejs/llhttp test/request), byte for byte where the gateway is stricter
    ("llhttp-cl-spaces-two-values", b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 4 2\r\n\r\nq=42", 16, "refuse", 400, LLHTTP + " (content-length.md): one length only"),
    ("llhttp-at-in-name", b"GET / HTTP/1.1\r\n" + H + b"Fo@: Failure\r\n\r\n", 16, "refuse", 400, LLHTTP + " (invalid.md): @ is not a token character"),
    ("llhttp-ctrl-in-name", b"GET / HTTP/1.1\r\n" + H + b"Foo\x01\ttest: Bar\r\n\r\n", 16, "refuse", 400, LLHTTP + " (invalid.md): a control byte in a field name"),
    ("llhttp-empty-name-2", b"GET / HTTP/1.1\r\n" + H + b": Bar\r\n\r\n", 16, "refuse", 400, LLHTTP + " (invalid.md): an empty field name"),
    ("llhttp-illegal-fold", b"GET / HTTP/1.1\r\n" + H + b"name\r\n : value\r\n\r\n", 16, "refuse", 400, LLHTTP + " (invalid.md): a line fold in a field name"),
    ("llhttp-corrupted-conn", b"GET / HTTP/1.1\r\n" + H + b"Connection\r\x1b5\xd5eep-Alive\r\n\r\n", 16, "refuse", 400, LLHTTP + " (invalid.md): control bytes inside a header"),
    ("llhttp-corrupted-name", b"GET / HTTP/1.1\r\n" + H + b"X-Some-Header\r\x1b5\xd5eep-Alive\r\n\r\n", 16, "refuse", 400, LLHTTP + " (invalid.md): control bytes inside a header name"),
    # llhttp accepts these in lenient mode and the gateway does not: its bare-lf, obs-fold and lenient-version
    # fixtures are already covered above (bare-lf, te-in-obs-fold) or as policy decisions (framing.version).
]
