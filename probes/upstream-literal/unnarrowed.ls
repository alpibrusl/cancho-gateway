edition 5;
fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock } = split(world);
    release(io);
    release(args);
    release(heap);
    release(clock);
    release(fs);
    release(ffi);
    var status = 1;
    borrow net as &n in {
        match tcp_connect(n, "127.0.0.1", 1) {
            Dialed::Ok(c) => { status = conn_close(c); }
            Dialed::Failed(e) => { status = 2; }
        }
    }
    release(net);
    return status;
}
