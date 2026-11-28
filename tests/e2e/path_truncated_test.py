import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import proxy_test as P


def send(gw, path):
    n0 = len(gw.log_lines())
    P.request(gw, b"GET " + path + b" HTTP/1.1\r\nHost: a\r\n\r\n")
    return gw.log_since(n0, 1)[0]


def main():
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        up = P.Upstream(P.free_port())
        gw = P.Gateway(tmp, P.free_port(), up.port, P.free_port(), P.free_port(), P.free_port())
        try:
            long_path = b"/echo/" + b"a" * 123      # 129 bytes
            exact_path = b"/echo/" + b"a" * 122     # 128 bytes

            line = send(gw, long_path)
            got = line.get("path", "")
            case_ok = got == long_path.decode()[:128] and len(got) == 128 and ("path_truncated" in line) and line["path_truncated"] is True
            print("129-byte path: cut to 128 and path_truncated set: " + ("ok" if case_ok else "FAIL %r" % (line,)))
            ok = ok and case_ok

            line = send(gw, exact_path)
            got = line.get("path", "")
            case_ok = got == exact_path.decode() and len(got) == 128 and "path_truncated" not in line
            print("128-byte path: whole and no path_truncated: " + ("ok" if case_ok else "FAIL %r" % (line,)))
            ok = ok and case_ok
        finally:
            gw.stop()
            up.stop = True
    sys.exit(0 if ok else 1)


main()
