edition 5;
fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock } = split(world);
    release(io);
    release(heap);
    release(clock);
    release(fs);
    release(ffi);
    let only = narrow(net, "127.0.0.1:9001");
    var status = 1;
    borrow args as &g in {
        borrow only as &n in {
            match tcp_connect(n, arg(g, 1), 9001) {
                Dialed::Ok(c) => { status = conn_close(c); }
                Dialed::Failed(e) => { status = 2; }
            }
        }
    }
    release(args);
    release(only);
    return status;
}
