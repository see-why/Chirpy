package main

import (
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	queries        *database.Queries
	platform       string
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
	if apiCfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Resetting metrics is only allowed in local environment"))
		return
	}

	err := apiCfg.queries.DeleteUser(req.Context())

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Internal server error"))
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	cfg.fileserverHits.Store(0)
	w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits.Load())))
}

func validateBody(body string) (string, error) {
	if body == "" {
		return body, errors.New("something went wrong")
	}

	if len(body) > 140 {
		return body, errors.New("chirp is too long")
	}

	words := strings.Split(body, " ")
	for ind, word := range words {
		lowerCaseWord := strings.ToLower(word)
		if lowerCaseWord == "kerfuffle" || lowerCaseWord == "sharbert" || lowerCaseWord == "fornax" {
			words[ind] = "****"
		}
	}

	return strings.Join(words, " "), nil
}

var apiCfg = &apiConfig{}

func main() {
	godotenv.Load()
	dbUrl := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")

	db, _ := sql.Open("postgres", dbUrl)
	dbQueries := database.New(db)

	apiCfg.queries = dbQueries
	apiCfg.platform = platform

	const filepathRoot = "."
	const addr = ":8080"

	m := http.NewServeMux()
	m.Handle("GET /app/", http.StripPrefix("/app", apiCfg.middlewareMetricInc(http.FileServer(http.Dir(filepathRoot)))))
	m.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(http.StatusText(http.StatusOK)))
	})
	m.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		type chirpParams struct {
			Body   string    `json:"body"`
			UserId uuid.UUID `json:"user_id"`
		}

		decoder := json.NewDecoder(req.Body)
		params := chirpParams{}
		err := decoder.Decode(&params)

		if err != nil || params.Body == "" || params.UserId == uuid.Nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid request"}`))
			return
		}

		params.Body, err = validateBody(params.Body)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "` + err.Error() + `"}`))
			return
		}

		createChirpParams := struct {
			UserID uuid.NullUUID
			Body   string
		}{
			UserID: uuid.NullUUID{UUID: params.UserId, Valid: true},
			Body:   params.Body,
		}

		chirp, err := apiCfg.queries.CreateChirp(req.Context(), createChirpParams)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		responseStruct := struct {
			Id         string    `json:"id"`
			CreateAt   time.Time `json:"created_at"`
			Updated_at time.Time `json:"updated_at"`
			Body       string    `json:"body"`
			UserId     string    `json:"user_id"`
		}{
			Id:         chirp.ID.String(),
			CreateAt:   chirp.CreatedAt,
			Updated_at: chirp.UpdatedAt,
			Body:       chirp.Body,
			UserId:     chirp.UserID.UUID.String(),
		}

		response, _ := json.Marshal(&responseStruct)
		w.Write([]byte(response))

	})
	m.HandleFunc("POST /api/users", func(w http.ResponseWriter, req *http.Request) {
		type userEmail struct {
			Email string `json:"email"`
		}

		decoder := json.NewDecoder(req.Body)
		params := userEmail{}
		err := decoder.Decode(&params)

		if err != nil || params.Email == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid request"}`))
			return
		}

		user, err := apiCfg.queries.CreateUser(req.Context(), params.Email)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		responseStruct := struct {
			Id         string    `json:"id"`
			CreateAt   time.Time `json:"created_at"`
			Updated_at time.Time `json:"updated_at"`
			Email      string    `json:"email"`
		}{
			Id:         user.ID.String(),
			CreateAt:   user.CreatedAt,
			Updated_at: user.UpdatedAt,
			Email:      user.Email,
		}

		response, _ := json.Marshal(&responseStruct)
		w.Write([]byte(response))
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
