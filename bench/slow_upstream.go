// The upstream of cell C5 (docs/bench.md): answers "ok" after a fixed delay. Run with GOMAXPROCS=1 on core 1.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"time"
)

func main() {
	port := flag.Int("port", 9000, "port to listen on")
	delay := flag.Duration("delay", 100*time.Millisecond, "how long to wait before answering")
	flag.Parse()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(*delay)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", *port), IdleTimeout: 10 * time.Minute}
	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}
