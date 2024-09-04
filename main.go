package main

import (
	"fmt"
	"net/http"
)

type configApi struct {
    fileserverHits int
}

func handlerReadiness(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(http.StatusText(http.StatusOK)))
}

func (cfg *configApi) middlewareMetricsInc(next *http.Handler) http.Handler {
    cfg.fileserverHits++
    return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
        next.ServeHTTP(w, r)
    })
}

func (cfg *configApi) hitCount(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("Content-Type", "text/plain; charset=utf-8")
    w.Write([]byte(fmt.Sprintf("Hits: %v", cfg.fileserverHits)))
}

func main() {
    filepathRoot := "."
    port := "8080"

    sm := http.NewServeMux()
    srv := http.Server{
        Handler: sm,
        Addr: ":" + port,
    }

    apiCfg := configApi {
        fileserverHits: 0,
    }

    sm.Handle("/app/", apiCfg.middlewareMetricsInc(&http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
    sm.Handle("/assets/logo.png", http.FileServer(http.Dir(filepathRoot)))
    sm.Handle("/pikachu.png", http.FileServer(http.Dir("./assets/")))
    sm.HandleFunc("/healthz", handlerReadiness)
    sm.HandleFunc("/metrics", apiCfg.hitCount)
    srv.ListenAndServe()
}
