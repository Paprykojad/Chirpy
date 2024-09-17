package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type configApi struct {
	fileserverHits int
	jwtSecret      string
}

type chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
    AuthorId int `json:"author_id"`
}

type user struct {
	Id       int `json:"id"`
	password []byte
	Email    string  `json:"email"`
	Token    *string `json:"token"`
    RefreshToken string `json:"refresh_token"`
    EpxDate time.Time `json:"exp_date"`
    Red bool `json:"is_chirpy_red"`
}

type chirps struct {
	Chirps []chirp `json:"chirps"`
	Users  []user  `json:"users"`
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

func wrapperDeleteChirp (crp *chirps, confApi *configApi) (http.HandlerFunc){
    return func (w http.ResponseWriter, r *http.Request) {
        tokenstr := r.Header.Get("Authorization")
        tokenstr = strings.TrimPrefix(tokenstr, "Bearer ")
        fmt.Println("Tokenstr:", tokenstr)

		claimsStruct := jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenstr, &claimsStruct, func(t *jwt.Token) (interface{}, error) { return []byte(confApi.jwtSecret), nil })
        fmt.Println("Rozpakowałem token")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

        strNum := strings.TrimPrefix(r.URL.Path, "/api/chirps/")
        num, _ := strconv.Atoi(strNum)

        fmt.Printf("Chirp Id: %v\n", num)

        for i, v := range crp.Chirps {
            if t, _ := token.Claims.GetSubject(); t == strconv.Itoa(v.Id) && v.AuthorId == num  {
                if date, _ := token.Claims.GetExpirationTime(); date.After(time.Now()) {
                    crp.Chirps[i].Id = len(crp.Chirps)+1
                    w.Header().Add("Content-Type", "application/json")
                    w.WriteHeader(204)
                    w.Write(nil)
                    return
                }
            }
        }
        http.Error(w, "Unauthorized", 403)
        return
    }
}

func wrapperWriteChirp (crp *chirps, confApi *configApi) (http.HandlerFunc){
    return func (w http.ResponseWriter, r *http.Request) {
        type requestBody struct {
            Body string `json:"body"`
        }
        tokenstr := r.Header.Get("Authorization")
        tokenstr = strings.TrimPrefix(tokenstr, "Bearer ")
        // fmt.Println("Tokenstr:", tokenstr)

		claimsStruct := jwt.RegisteredClaims{}
		// fmt.Printf("tokenstr: %v \njwtSecret: %v\n\n", tokenstr, confApi.jwtSecret)
		token, err := jwt.ParseWithClaims(tokenstr, &claimsStruct, func(t *jwt.Token) (interface{}, error) { return []byte(confApi.jwtSecret), nil })
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

        for _, v := range crp.Users {
            // tt, _ := token.Claims.GetSubject()
            // fmt.Printf("t: %v\n", tt)
            if t, _ := token.Claims.GetSubject(); t == strconv.Itoa(v.Id)  {
                if date, _ := token.Claims.GetExpirationTime(); date.After(time.Now()) {
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

                    authorIdInt, err := strconv.Atoi(t)
                    chirp := chirp{
                        Id:   len(crp.Chirps) + 1,
                        Body: body,
                        AuthorId: authorIdInt,
                    }
                    // fmt.Println("Appending:", chirp)
                    crp.Chirps = append(crp.Chirps, chirp)

                    if err = crp.writeDatabase(); err != nil {
                        http.Error(w, "Database broke down", 400)
                        return
                    }

                    w.Header().Add("Content-Type", "application/json")
                    w.WriteHeader(201)
                    jchirp, err := json.Marshal(chirp)
                    w.Write(jchirp)
                    return
                }
            }
        }
        http.Error(w, "Unauthorized", 401)
        return
    }
}

func (crp *chirps) writeDatabase() error {
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

func (crp *chirps) readChirps(w http.ResponseWriter, r *http.Request) {
	chi, _ := json.MarshalIndent(crp.Chirps, "", "    ")
	fmt.Println("Stored chirps:", string(chi))

	path := r.URL.Path
	if path != "/api/chirps/" && path != "/api/chirps" {
		path, _ := strings.CutPrefix(path, "/api/chirps/")
		id, _ := strconv.Atoi(path)
		if id > len(crp.Chirps) || id <= 0 {
			http.Error(w, fmt.Sprintf("Chirp id:%v does not exist", id), 404)
			return
		}
		jresp, _ := json.Marshal(crp.Chirps[id-1])
		w.Header().Add("Content-Type", "application/json")
		w.Write(jresp)
		return
	}

    if r.URL.Query().Get("author_id") != "" || r.URL.Query().Get("sort") != "" {
        id := r.URL.Query().Get("author_id")
        idint, _ := strconv.Atoi(id)
        userschirps := []chirp{}

        sort := r.URL.Query().Get("sort")
        switch sort {
        case "asc":
            fmt.Println("Ascending order")
            for i := 0; i < len(crp.Chirps); i++ {
                if id == "" {
                    userschirps = append(userschirps, crp.Chirps[i])
                } else if crp.Chirps[i].AuthorId == idint {
                    userschirps = append(userschirps, crp.Chirps[i])
                }
            }
        case "desc":
            fmt.Println("Descending order")
            for i := len(crp.Chirps)-1; i >= 0; i-- {
                if id == "" {
                    userschirps = append(userschirps, crp.Chirps[i])
                } else if crp.Chirps[i].AuthorId == idint {
                    userschirps = append(userschirps, crp.Chirps[i])
                }
            }
        default:
            http.Error(w, fmt.Sprintf("Sorting method \"%v\" is not available\n"), 400)
        }

        jresp, _ := json.Marshal(userschirps)
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

func (crp *chirps) addUser(w http.ResponseWriter, r *http.Request) {
	type userData struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	type userDataResponse struct {
		Id    int    `json:"id"`
		Email string `json:"email"`
        Red bool `json:"is_chirpy_red"`
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
		Email:    reqBody.Email,
		Id:       len(crp.Users) + 1,
	}
	crp.Users = append(crp.Users, user)

	if err = crp.writeDatabase(); err != nil {
		http.Error(w, "Database error", 400)
	}

	userDataResp := userDataResponse{
		Id:    crp.Users[len(crp.Users)-1].Id,
		Email: crp.Users[len(crp.Users)-1].Email,
		Red: crp.Users[len(crp.Users)-1].Red,
	}

	w.WriteHeader(201)
	jresp, _ := json.Marshal(userDataResp)
	w.Write(jresp)
}

func wrapperLogin(crp *chirps, confApi *configApi) (login http.HandlerFunc) {
    return func (w http.ResponseWriter, r *http.Request)  {
        type userData struct {
            Password string `json:"password"`
            Email    string `json:"email"`
        }
        type userDataResponse struct {
            Id    int    `json:"id"`
            Email string `json:"email"`
            Token string `json:"token"`
            RefreshToken string `json:"refresh_token"`
            Red bool `json:"is_chirpy_red"`
        }

        reqBody := userData{}
        decoder := json.NewDecoder(r.Body)
        err := decoder.Decode(&reqBody)
        if err != nil {
            http.Error(w, err.Error(), 400)
            return
        }

        refreshToken := make([]byte, 32)
        rand.Read(refreshToken)
        refreshTokenString := hex.EncodeToString(refreshToken)

        for i, v := range crp.Users {
            if v.Email == reqBody.Email {
                crp.Users[i].RefreshToken = refreshTokenString
                crp.Users[i].EpxDate = time.Now().Add(time.Hour * 24 * 60)
            }
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
            Issuer:   "chirpy",
            IssuedAt: jwt.NewNumericDate(time.Now()),
            ExpiresAt: func() *jwt.NumericDate {
                for _, v := range crp.Users {
                    if v.Email == reqBody.Email {
                        return jwt.NewNumericDate(time.Now().Add(time.Hour * 1))
                    }
                }
                return jwt.NewNumericDate(time.Now().Add(time.Hour * 1))
            }(),
            Subject: func() string {
                for _, v := range crp.Users {
                    if v.Email == reqBody.Email {
                        return strconv.Itoa(v.Id)
                    }
                }
                http.Error(w, "User does not exist", 401)
                return ""
            }(),
        })
        // fmt.Println("Token:", token)

        tokenString, err := token.SignedString([]byte(confApi.jwtSecret))
        if err != nil {
            http.Error(w, err.Error(), 400)
            return
        }
        // fmt.Println("Token String:", tokenString)

        for _, v := range crp.Users {
            if v.Email == reqBody.Email {
                err = bcrypt.CompareHashAndPassword(v.password, []byte(reqBody.Password))
                if err != nil {
                    http.Error(w, "Unauthorized", 401)
                    return
                } else {
                    w.Header().Add("Content-Type", "application/json")
                    w.WriteHeader(200)
                    v.Token = &tokenString
                    userDataResp := userDataResponse{
                        Id:    v.Id,
                        Email: v.Email,
                        Token: tokenString,
                        RefreshToken: refreshTokenString,
                        Red: v.Red,
                    }
                    jresp, _ := json.MarshalIndent(userDataResp, "", "    ")
                    // fmt.Println("Sending back:", string(jresp))
                    w.Write(jresp)
                    return
                }
            }
        }
    }
}

func wrapperUpdateUser(crps *chirps, confApi *configApi) (updateUser http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenstr := r.Header.Get("Authorization")
		// fmt.Println("Tokenstr:", tokenstr)
		tokenstrarr := strings.Split(tokenstr, " ")
		if len(tokenstrarr) <= 1 {
			http.Error(w, fmt.Sprintf("Unathorized (token: \"%v\")", tokenstr), 401)
			return
		}
		tokenstr = tokenstrarr[1]
		// fmt.Println("Tokenstr:", tokenstr)

		claimsStruct := jwt.RegisteredClaims{}
		// fmt.Printf("tokenstr: %v \njwtSecret: %v\n\n", tokenstr, confApi.jwtSecret)
		token, err := jwt.ParseWithClaims(tokenstr, &claimsStruct, func(t *jwt.Token) (interface{}, error) { return []byte(confApi.jwtSecret), nil })
		if err != nil {
			http.Error(w, "Unauthorized (cannot parse)", 401)
			return
		}
		if expiration, _ := token.Claims.GetExpirationTime(); time.Now().After(expiration.Time) {
			http.Error(w, "Unauthorized (token expired)", 401)
			return
		}
		if issuer, _ := token.Claims.GetIssuer(); issuer != "chirpy" {
			http.Error(w, "Unauthorized (issuer is not chirpy)", 401)
			return
		}

		type request struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		reqBody := request{}

		decoder := json.NewDecoder(r.Body)
		defer r.Body.Close()
		err = decoder.Decode(&reqBody)
		if err != nil {
			http.Error(w, "Bad data", 400)
			return
		}

		type response struct {
			Id    int    `json:"id"`
			Email string `json:"email"`
            Red bool `json:"is_chirpy_red"`
		}

		userId, _ := token.Claims.GetSubject()
		for i, v := range crps.Users {
			if t, _ := strconv.Atoi(userId); t == v.Id {
				crps.Users[i].Email = reqBody.Email
				passwd, _ := bcrypt.GenerateFromPassword([]byte(reqBody.Password), bcrypt.DefaultCost)
				crps.Users[i].password = passwd

				jresp, _ := json.Marshal(response{
					Id:    crps.Users[i].Id,
					Email: crps.Users[i].Email,
					Red: crps.Users[i].Red,
				})
				w.Write(jresp)
				return
			}
		}

	}
}

func wrapperRefreshToken (crp *chirps, confApi *configApi) (http.HandlerFunc) {
    return func (w http.ResponseWriter, r *http.Request) {

        type resp struct {
            TokenStr string `json:"token"`
        }

        refToken := r.Header.Get("Authorization")
        refToken = strings.TrimPrefix(refToken, "Bearer ")
        // fmt.Printf("Recieved refresh token: %v\n", refToken)
        for _, v := range crp.Users {
            fmt.Printf("v.RefreshToken: %v\n", v.RefreshToken)
            if v.RefreshToken == refToken && v.EpxDate.After(time.Now()){
                token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
                    Issuer:   "chirpy",
                    IssuedAt: jwt.NewNumericDate(time.Now()),
                    ExpiresAt: func() *jwt.NumericDate {
                        return jwt.NewNumericDate(time.Now().Add(time.Hour * 1))
                    }(),
                    Subject: func() string {
                        return strconv.Itoa(v.Id)
                    }(),
                })
                tokenStr, err := token.SignedString([]byte(confApi.jwtSecret))
                if err != nil {
                    http.Error(w, err.Error(), 400)
                    return
                }

                response := resp{
                    TokenStr: tokenStr,
                }
                jresp, _ := json.Marshal(response)
                w.Write(jresp)
                return
            }
        }
        http.Error(w, "", 401)
    }
}


func wrapperRevokeToken (crp *chirps, confApi *configApi) (http.HandlerFunc) {
    return func (w http.ResponseWriter, r *http.Request) {
        type resp struct {
            TokenStr string `json:"token"`
        }

        refToken := r.Header.Get("Authorization")
        refToken = strings.TrimPrefix(refToken, "Bearer ")
        // fmt.Printf("Recieved refresh token: %v\n", refToken)
        for i, v := range crp.Users {
            fmt.Printf("v.RefreshToken: %v\n", v.RefreshToken)
            if v.RefreshToken == refToken && v.EpxDate.After(time.Now()){
                crp.Users[i].RefreshToken = ""
                crp.Users[i].EpxDate = time.Now()
                w.WriteHeader(204)
                w.Write(nil)
            }
        }
        http.Error(w, "", 401)
    }
}

func (crp *chirps) makeRed (w http.ResponseWriter, r *http.Request) {
    type requestBody struct {
        Event string `json:"event"`
        Data  struct {
            UserID int `json:"user_id"`
        } `json:"data"`
    }

    tokenstr := r.Header.Get("Authorization")
    tokenstr = strings.TrimPrefix(tokenstr, "ApiKey ")

    if tokenstr != os.Getenv("POLKA_KEY") {
        http.Error(w, "", 401)
        return
    }

    req := requestBody{}
    decoder := json.NewDecoder(r.Body)
    err := decoder.Decode(&req)
    if err != nil {
        http.Error(w, err.Error(), 400)
    }
    fmt.Println("Request:", req)

    if req.Event != "user.upgraded" {
        http.Error(w, "", 204)
        return
    }

    for i, v := range crp.Users {
        if v.Id == req.Data.UserID {
            crp.Users[i].Red = true
            w.WriteHeader(204)
            w.Write(nil)
            return
        }
    }

    http.Error(w, "", 404)
    return
}

func main() {
	os.Remove("database.json")
	godotenv.Load(".env")

	const filepathRoot string = "."
	port := os.Getenv("PORT")

	mux := http.NewServeMux()
	srv := http.Server{
		Handler: mux,
		Addr:    ":" + port,
	}

	apiCfg := configApi{
		fileserverHits: 0,
		jwtSecret:      os.Getenv("JWT_SECRET"),
	}

	crps := chirps{
		Chirps: []chirp{},
		Users:  []user{},
	}

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
	mux.Handle("/assets/logo.png", http.FileServer(http.Dir(filepathRoot)))
	mux.Handle("/pikachu.png", http.FileServer(http.Dir("./assets/")))
	mux.HandleFunc("POST /api/chirps", wrapperWriteChirp(&crps, &apiCfg))
	mux.HandleFunc("DELETE /api/chirps/", wrapperDeleteChirp(&crps, &apiCfg))
	mux.HandleFunc("GET /api/chirps/", crps.readChirps)
	mux.HandleFunc("POST /api/users", crps.addUser)
	mux.HandleFunc("PUT /api/users", wrapperUpdateUser(&crps, &apiCfg))
	mux.HandleFunc("/api/login", wrapperLogin(&crps, &apiCfg))
	mux.HandleFunc("GET /api/healthz", handlerReadiness)
    mux.HandleFunc("POST /api/refresh", wrapperRefreshToken(&crps, &apiCfg))
    mux.HandleFunc("post /api/revoke", wrapperRevokeToken(&crps, &apiCfg))
	mux.HandleFunc("GET /api/metrics", apiCfg.hitCount)
	mux.HandleFunc("GET /admin/metrics", apiCfg.hitCountAdmin)
	mux.HandleFunc("/api/reset", apiCfg.resetCount)
    mux.HandleFunc("POST /api/polka/webhooks", crps.makeRed)

	fmt.Println("Serving on port:", port)
	srv.ListenAndServe()
}
