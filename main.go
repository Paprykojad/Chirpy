package main

import (
    "net/http"
)

func main() {
    filepathRoot := "."
    port := "8080"

    sm := http.NewServeMux()
    srv := http.Server{
        Handler: sm,
        Addr: ":" + port,
    }

    sm.Handle("/", http.FileServer(http.Dir(filepathRoot)))
    sm.Handle("/assets/logo.png", http.FileServer(http.Dir(filepathRoot)))
    sm.Handle("/pikachu.png", http.FileServer(http.Dir("./assets/")))
    srv.ListenAndServe()
}
