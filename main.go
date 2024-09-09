package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

type configApi struct {
    fileserverHits int
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

func emoji(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "./assets/emoji.html")
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

func noProfaneWords(s string) string {
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
    return strings.Join(sa, " ")
}

func validateChirp(w http.ResponseWriter, r *http.Request) {
    type responseBodyOk struct {
        Cleaned_body string `json:"cleaned_body"`
    }
    type responseBodyNotOk struct {
        Error string `json:"error"`
    }
    type requestBody struct {
        Body string `json:"body"`
    }
    w.Header().Add("Content-Type", "application/json")

    reqBody := requestBody{}

    decoder := json.NewDecoder(r.Body)
    defer r.Body.Close()
    err := decoder.Decode(&reqBody)
    // fmt.Println("Request struct:", reqBody.Body)

    if err != nil {
        // fmt.Println("Error with decoding json")
        respBody := responseBodyNotOk{
            Error: "Something went wrong",
        }
        w.WriteHeader(400)
        json, _ := json.Marshal(respBody)
        w.Write([]byte(json))
        return
    } 

    if len(reqBody.Body) > 140 {
        // fmt.Println("Chirp is too long")
        respBody := responseBodyNotOk{
            Error: "Chirp was too long",
        }
        w.WriteHeader(400)
        var jsn []byte
        jsn, _ = json.Marshal(respBody)
        w.Write([]byte(jsn))
        return
    }

    respBody := responseBodyOk{
        Cleaned_body: noProfaneWords(reqBody.Body),
    }
    jres, _ := json.Marshal(respBody)
    w.Write(jres)
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

    // sm.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
    sm.Handle("/assets/logo.png", http.FileServer(http.Dir(filepathRoot)))
    sm.Handle("/pikachu.png", http.FileServer(http.Dir("./assets/")))
    sm.HandleFunc("/", emoji)
    sm.HandleFunc("POST /api/validate_chirp", validateChirp)
    sm.HandleFunc("GET /api/healthz", handlerReadiness)
    sm.HandleFunc("GET /api/metrics", apiCfg.hitCount)
    sm.HandleFunc("GET /admin/metrics", apiCfg.hitCountAdmin)
    sm.HandleFunc("/api/reset", apiCfg.resetCount)
    srv.ListenAndServe()
}
