-- wrk script for cell C4 (docs/bench.md): POST /post with a 16 KiB body.
wrk.method = "POST"
wrk.body = string.rep("x", 16384)
wrk.headers["Content-Type"] = "application/octet-stream"
