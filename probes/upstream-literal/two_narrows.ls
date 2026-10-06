edition 5;
fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock } = split(world);
    release(io);
    release(heap);
    release(clock);
    release(fs);
    release(ffi);
    release(args);
    let a = narrow(net, "127.0.0.1:9001");
    let b = narrow(net, "127.0.0.2:9002");
    release(a);
    release(b);
    return 0;
}
