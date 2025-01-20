package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		fmt.Printf("Hits: %d\n", cfg.fileserverHits.Load())
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) middlewareGetMetrics(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(
		`<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited ` + fmt.Sprint(cfg.fileserverHits.Load()) + ` times!</p>
			</body>
		</html>
		`))
}

func (cfg *apiConfig) middlewareResetMetrics(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	cfg.fileserverHits.Store(0)
	w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits.Load())))
}

var apiCfg = &apiConfig{}

func main() {
	const filepathRoot = "."
	const addr = ":8080"

	m := http.NewServeMux()
	m.Handle("GET /app/", http.StripPrefix("/app", apiCfg.middlewareMetricInc(http.FileServer(http.Dir(filepathRoot)))))
	m.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(http.StatusText(http.StatusOK)))
	})
	m.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, req *http.Request) {
		type chirp struct {
			Body string `json:"body"`
		}

		decoder := json.NewDecoder(req.Body)
		params := chirp{}
		err := decoder.Decode(&params)
		fmt.Printf("Request Body Length: %d \n", len(params.Body))

		type errorResponse struct {
			Error string `json:"error"`
		}

		if err != nil || params.Body == "" {
			fmt.Printf("Error decoding params: %s \n", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")

			resp := errorResponse{Error: "Something went wrong"}
			respBody, _ := json.Marshal(resp)

			w.Write([]byte(respBody))
			return
		}

		if len(params.Body) > 140 {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")

			resp := errorResponse{Error: "Chirp is too long"}
			respBody, _ := json.Marshal(resp)

			w.Write([]byte(respBody))
			return
		}

		words := strings.Split(params.Body, " ")
		for ind, word := range words {
			lowerCaseWord := strings.ToLower(word)
			if lowerCaseWord == "kerfuffle" || lowerCaseWord == "sharbert" || lowerCaseWord == "fornax" {
				words[ind] = "****"
			}
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		resp := struct {
			CleanedBody string `json:"cleaned_body"`
		}{CleanedBody: strings.Join(words, " ")}
		respBody, _ := json.Marshal(resp)
		w.Write([]byte(respBody))
	})
	m.HandleFunc("GET /admin/metrics", apiCfg.middlewareGetMetrics)
	m.HandleFunc("POST /admin/reset", apiCfg.middlewareResetMetrics)

	srv := http.Server{
		Handler:      m,
		Addr:         addr,
		WriteTimeout: 30 * time.Second,
		ReadTimeout:  30 * time.Second,
	}

	// this blocks forever, until the server
	// has an unrecoverable error
	fmt.Println("server started on ", addr)
	err := srv.ListenAndServe()
	log.Fatal(err)
}
