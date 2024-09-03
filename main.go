package main

import (
    "net/http"
)

func main() {
    sm := http.NewServeMux()
    srv := http.Server{
        Handler: sm,
        Addr: ":8080",
    }

    sm.Handle("/", http.FileServer(http.Dir(".")))
    srv.ListenAndServe()
}
