package main

import (
    "golang.org/x/crypto/bcrypt"
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strconv"
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

type user struct {
    Id int `json:"id"`
    password []byte 
    Email string `json:"email"`
}

type chirps struct {
    Chirps []chirp `json:"chirps"`
    Users []user `json:"users"`
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

    if err = crp.writeDatabase(); err != nil {
        http.Error(w, "Database broke down", 400)
    }

    w.Header().Add("Content-Type", "application/json")
    w.WriteHeader(201)
    jchirp, err := json.Marshal(chirp)
    w.Write(jchirp)
}

func (crp *chirps) writeDatabase() (error) {
    jsonChirps, err := json.MarshalIndent(crp, "", "    ")
    if err != nil {
        return err
    }

    var mu sync.Mutex
    mu.Lock()
    file, err := os.Create("database.json")
    if err != nil {
        return err
    }
    defer file.Close()
    writer := bufio.NewWriter(file)
    _, err = writer.Write(jsonChirps)
    writer.Flush()
    if err != nil {
        return err
    }
    mu.Unlock()

    return nil
}

func (crp *chirps) readChirps (w http.ResponseWriter, r *http.Request) {

    chi, _ := json.MarshalIndent(crp.Chirps, "", "    ")
    fmt.Println("Stored chirps:", string(chi))

    path := r.URL.Path
    if path != "/api/chirps/" || path != "/api/chirps" {
        path, _ := strings.CutPrefix(path, "/api/chirps/")
        id, _ := strconv.Atoi(path)
        if id > len(crp.Chirps) {
            http.Error(w, fmt.Sprintf("Chirp id:%v does not exist", id), 404)
            return
        }
        jresp, _ := json.Marshal(crp.Chirps[id-1])
        w.Header().Add("Content-Type", "application/json")
        w.Write(jresp)
        return
    }

    jsonFile, err := os.Open("database.json")
    if err != nil {
        return
    }
    defer jsonFile.Close()

    byteValue, err := io.ReadAll(jsonFile)
    if err != nil {
        return
    }

    crps := chirps{}
    err = json.Unmarshal(byteValue, &crps)
    fmt.Println("request body:", string(byteValue))
    fmt.Println(err)
    if err != nil {
        http.Error(w, "Could not unmarshall request body", 400)
        return
    }

    w.Header().Add("Content-Type", "application/json")
    // w.WriteHeader(201)
    jchirps, err := json.Marshal(crp.Chirps)
    w.Write(jchirps)
}

func (crp *chirps) addUser (w http.ResponseWriter, r *http.Request) {
    type userData struct {
        Password string `json:"password"`
        Email string `json:"email"`
    }

    type userDataResponse struct {
        Id int `json:"id"`
        Email string `json:"email"`
    }

    reqBody := userData{}
    decoder := json.NewDecoder(r.Body)
    defer r.Body.Close()
    err := decoder.Decode(&reqBody)
    if err != nil {
        http.Error(w, err.Error(), 400)
        return
    }
    passwd, _ := bcrypt.GenerateFromPassword([]byte(reqBody.Password), bcrypt.DefaultCost)
    reqBody.Password = string(passwd)
    var user user = user{
        password: []byte(reqBody.Password),
        Email: reqBody.Email,
        Id: len(crp.Users)+1,
    }
    crp.Users = append(crp.Users, user)

    if err = crp.writeDatabase(); err != nil {
        http.Error(w, "Database error", 400)
    }

    userDataResp := userDataResponse{
        Id: crp.Users[len(crp.Users)-1].Id,
        Email: crp.Users[len(crp.Users)-1].Email,
    }

    w.WriteHeader(201)
    jresp, _ := json.Marshal(userDataResp)
    w.Write(jresp)
}

func (crp *chirps) login (w http.ResponseWriter, r *http.Request) {
    type userData struct {
        Password string `json:"password"`
        Email string `json:"email"`
    }
    type userDataResponse struct {
        Id int `json:"id"`
        Email string `json:"email"`
    }

    reqBody := userData{}
    decoder := json.NewDecoder(r.Body)
    err := decoder.Decode(&reqBody)
    if err != nil {
        http.Error(w,err.Error(), 400)
        return
    }
    for _, v := range crp.Users {
        if v.Email == reqBody.Email {
            err = bcrypt.CompareHashAndPassword(v.password, []byte(reqBody.Password))
            if err != nil {
                http.Error(w, "Unauthorized", 401)
                return
            } else {
                w.Header().Add("Content-Type", "application/json")
                w.WriteHeader(200)
                userDataResp := userDataResponse{
                    Id: v.Id,
                    Email: v.Email,
                }
                jresp, _ := json.Marshal(userDataResp)
                w.Write(jresp)
                return
            }
        }
    }
}

func main() {
    os.Remove("database.json")
    filepathRoot := "."
    port := "8080"

    mux := http.NewServeMux()
    srv := http.Server{
        Handler: mux,
        Addr: ":" + port,
    }

    apiCfg := configApi {
        fileserverHits: 0,
    }

    crps := chirps{
        Chirps: []chirp{},
        Users: []user{},
    }

    mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
    mux.Handle("/assets/logo.png", http.FileServer(http.Dir(filepathRoot)))
    mux.Handle("/pikachu.png", http.FileServer(http.Dir("./assets/")))
    mux.HandleFunc("POST /api/chirps", crps.writeChirp)
    mux.HandleFunc("GET /api/chirps/", crps.readChirps)
    mux.HandleFunc("POST /api/users", crps.addUser)
    mux.HandleFunc("/api/login", crps.login)
    mux.HandleFunc("GET /api/healthz", handlerReadiness)
    mux.HandleFunc("GET /api/metrics", apiCfg.hitCount)
    mux.HandleFunc("GET /admin/metrics", apiCfg.hitCountAdmin)
    mux.HandleFunc("/api/reset", apiCfg.resetCount)
    
    fmt.Println("Serving on port:", port)
    srv.ListenAndServe()
}
