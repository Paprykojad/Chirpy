package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"
	"sync"
)

type configApi struct {
    fileserverHits int
}

type chirp struct {
    Id int `json:"id"`
    Body string `json:"body"`
}

type chirps struct {
    Chirps []chirp `json:"chirps"`
}

func handlerReadiness(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(http.StatusText(http.StatusOK)))
}

func (cfg *configApi) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *configApi) resetCount(w http.ResponseWriter, r *http.Request) {
    cfg.fileserverHits = 0
}

func (cfg *configApi) hitCountAdmin(w http.ResponseWriter, r *http.Request) {
    // w.Header().Add("Content-Type", "text/plain; charset=utf-8")
    t, err := template.ParseFiles("./admin/index.html")
    if err != nil {
        http.Error(w, "Unable to load template", http.StatusInternalServerError)
		return
    }
    err = t.Execute(w, cfg.fileserverHits)
    if err != nil {
        http.Error(w, "Unable to render template", http.StatusInternalServerError)
		return
    }
}

func (cfg *configApi) hitCount(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("Content-Type", "text/plain; charset=utf-8")
    w.Write([]byte(fmt.Sprintf("Hits: %v", cfg.fileserverHits)))
}

func noProfaneWords(s string) (string, error) {
    if len(s) > 140 {
        return "", fmt.Errorf("Chirp was too long")
    }
    sa := strings.Split(s, " ")
    for i, v := range sa {
        v = strings.ToLower(v)
        switch v {
        case "kerfuffle":
            sa[i] = "****"
        case "sharbert":
            sa[i] = "****"
        case "fornax":
            sa[i] = "****"
        }
    }
    return strings.Join(sa, " "), nil
}

func (crp *chirps) writeChirp (w http.ResponseWriter, r *http.Request) {
    type requestBody struct {
        Body string `json:"body"`
    }

    reqBody := requestBody{}
    decoder := json.NewDecoder(r.Body)
    defer r.Body.Close()
    err := decoder.Decode(&reqBody)
    if err != nil {
        http.Error(w, "Something went wrong", 400)
        return
    }
    body, err := noProfaneWords(reqBody.Body)
    if err != nil {
        http.Error(w, "Chirp was too long", 400)
        return
    }

    chirp := chirp{
        Id: len(crp.Chirps)+1,
        Body: body,
    }
    crp.Chirps = append(crp.Chirps, chirp)

    jsonChirps, err := json.MarshalIndent(crp, "", "    ")
    if err != nil {
        http.Error(w, "Something went wrong", 400)
        return
    }

    var mu sync.Mutex
    mu.Lock()
    file, err := os.Create("database.json")
    if err != nil {
        http.Error(w, "Something went wrong", 400)
        return
    }
    defer file.Close()
    writer := bufio.NewWriter(file)
    _, err = writer.Write(jsonChirps)
    if err != nil {
        http.Error(w, "Something went wrong", 400)
        return
    }
    mu.Unlock()

    w.Header().Add("Content-Type", "application/json")
    w.WriteHeader(201)
    w.
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

<<<<<<< Updated upstream
    crps := chirps{
        Chirps: []chirp{},
    }

    sm.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
    sm.Handle("/assets/logo.png", http.FileServer(http.Dir(filepathRoot)))
    sm.Handle("/pikachu.png", http.FileServer(http.Dir("./assets/")))
    sm.HandleFunc("POST /api/chirps", crps.writeChirp)
=======
    sm.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
    sm.Handle("/assets/logo.png", http.FileServer(http.Dir(filepathRoot)))
    sm.Handle("/pikachu.png", http.FileServer(http.Dir("./assets/")))
    sm.HandleFunc("POST /api/validate_chirp", validateChirp)
>>>>>>> Stashed changes
    sm.HandleFunc("GET /api/healthz", handlerReadiness)
    sm.HandleFunc("GET /api/metrics", apiCfg.hitCount)
    sm.HandleFunc("GET /admin/metrics", apiCfg.hitCountAdmin)
    sm.HandleFunc("/api/reset", apiCfg.resetCount)
    srv.ListenAndServe()
}
