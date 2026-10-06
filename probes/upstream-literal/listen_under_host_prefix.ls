edition 5;
fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock } = split(world);
    release(io);
    release(heap);
    release(clock);
    release(fs);
    release(ffi);
    release(args);
    let only = narrow(net, "127.0.0.");
    var status = 1;
    borrow only as &n in {
        match tcp_listen(n, 9001, 16, 0) {
            Listening::Ok(l) => { var lh = l; status = listener_close(lh); }
            Listening::Failed(e) => { status = 2; }
        }
    }
    release(only);
    return status;
}
