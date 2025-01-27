package main

import (
	auth "chirpy/internal"
	"chirpy/internal/database"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
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
	tokenSecret    string
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

func validateAndCheckEmail(email string, queries *database.Queries, ctx context.Context) (database.User, error) {
	emailFormat := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, err := regexp.MatchString(emailFormat, email)
	if err != nil || !matched {
		return database.User{}, errors.New("invalid email")
	}

	user, err := queries.GetUserByEmail(ctx, email)
	if err == nil {
		return user, errors.New("email already exists")
	}

	return database.User{}, nil
}

var apiCfg = &apiConfig{}

func main() {
	godotenv.Load()
	dbUrl := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	tokenSecret := os.Getenv("JWT_SECRET")

	db, _ := sql.Open("postgres", dbUrl)
	dbQueries := database.New(db)

	apiCfg.queries = dbQueries
	apiCfg.platform = platform
	apiCfg.tokenSecret = tokenSecret

	const filepathRoot = "."
	const addr = ":8080"

	m := http.NewServeMux()
	m.Handle("GET /app/", http.StripPrefix("/app", apiCfg.middlewareMetricInc(http.FileServer(http.Dir(filepathRoot)))))
	m.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(http.StatusText(http.StatusOK)))
	})
	m.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, req *http.Request) {
		chirpID := strings.TrimPrefix(req.URL.Path, "/api/chirps/")
		chirpUUID, err := uuid.Parse(chirpID)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid chirp ID"}`))
			return
		}

		chirp, err := apiCfg.queries.SelectChirp(req.Context(), chirpUUID)

		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				w.WriteHeader(http.StatusNotFound)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Write([]byte(`{"error": "Chirp not found"}`))
				return
			}
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		type chirpResponse struct {
			Id         string    `json:"id"`
			CreateAt   time.Time `json:"created_at"`
			Updated_at time.Time `json:"updated_at"`
			Body       string    `json:"body"`
			UserId     string    `json:"user_id"`
		}

		response := chirpResponse{
			Id:         chirp.ID.String(),
			CreateAt:   chirp.CreatedAt,
			Updated_at: chirp.UpdatedAt,
			Body:       chirp.Body,
			UserId:     chirp.UserID.UUID.String(),
		}

		responseJSON, _ := json.Marshal(&response)
		w.Write([]byte(responseJSON))
	})
	m.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		chirps, err := apiCfg.queries.SelectChirps(req.Context())

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		type chirpResponse struct {
			Id         string    `json:"id"`
			CreateAt   time.Time `json:"created_at"`
			Updated_at time.Time `json:"updated_at"`
			Body       string    `json:"body"`
			UserId     string    `json:"user_id"`
		}

		response := make([]chirpResponse, len(chirps))

		for i, chirp := range chirps {
			response[i] = chirpResponse{
				Id:         chirp.ID.String(),
				CreateAt:   chirp.CreatedAt,
				Updated_at: chirp.UpdatedAt,
				Body:       chirp.Body,
				UserId:     chirp.UserID.UUID.String(),
			}
		}

		responseJSON, _ := json.Marshal(&response)
		w.Write([]byte(responseJSON))
	})
	m.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerTokenFromHeader(req.Header)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized Request"}`))
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.tokenSecret)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Token is invalid"}`))
			return
		}

		type chirpParams struct {
			Body   string    `json:"body"`
			UserId uuid.UUID `json:"user_id"`
		}

		decoder := json.NewDecoder(req.Body)
		params := chirpParams{}
		err = decoder.Decode(&params)

		params.UserId = userID

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
	m.HandleFunc("GET /api/users", func(w http.ResponseWriter, req *http.Request) {
		users, err := apiCfg.queries.SelectUsers(req.Context())

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		type userResponse struct {
			Id         string    `json:"id"`
			CreateAt   time.Time `json:"created_at"`
			Updated_at time.Time `json:"updated_at"`
			Email      string    `json:"email"`
		}

		response := make([]userResponse, len(users))

		for i, user := range users {
			response[i] = userResponse{
				Id:         user.ID.String(),
				CreateAt:   user.CreatedAt,
				Updated_at: user.UpdatedAt,
				Email:      user.Email,
			}
		}

		responseJSON, _ := json.Marshal(&response)
		w.Write([]byte(responseJSON))
	})
	m.HandleFunc("POST /api/users", func(w http.ResponseWriter, req *http.Request) {
		type userEmail struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(req.Body)
		params := userEmail{}
		err := decoder.Decode(&params)

		if err != nil || params.Email == "" || params.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid request"}`))
			return
		}

		_, err = validateAndCheckEmail(params.Email, apiCfg.queries, req.Context())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, err.Error())))
			return
		}

		hashedPassord, err := auth.HashPassword(params.Password)

		if err != nil {
			fmt.Printf("error hashing password: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid password"}`))
			return
		}

		createUserParams := database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hashedPassord,
		}

		user, err := apiCfg.queries.CreateUser(req.Context(), createUserParams)

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
	m.HandleFunc("PUT /api/users", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerTokenFromHeader(req.Header)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized Request"}`))
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.tokenSecret)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Token is invalid"}`))
			return
		}

		type userParams struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		params := userParams{}

		decoder := json.NewDecoder(req.Body)
		err = decoder.Decode(&params)

		if err != nil || params.Email == "" || params.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid request"}`))
			return
		}

		_, err = validateAndCheckEmail(params.Email, apiCfg.queries, req.Context())

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, err.Error())))
			return
		}

		hashedPassord, err := auth.HashPassword(params.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid password"}`))
			return
		}

		updateUserParams := database.UpdateUserParams{
			Email:          params.Email,
			HashedPassword: hashedPassord,
			ID:             userID,
		}

		user, err := apiCfg.queries.UpdateUser(req.Context(), updateUserParams)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

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

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		response, _ := json.Marshal(&responseStruct)
		w.Write([]byte(response))

	})
	m.HandleFunc("GET /admin/metrics", apiCfg.middlewareGetMetrics)
	m.HandleFunc("POST /admin/reset", apiCfg.middlewareResetMetrics)
	m.HandleFunc("POST /api/login", func(w http.ResponseWriter, req *http.Request) {
		var params struct {
			Email            string `json:"email"`
			Password         string `json:"password"`
			ExpiresInSeconds int    `json:"expires_in_seconds"`
		}

		decoder := json.NewDecoder(req.Body)
		err := decoder.Decode(&params)

		if err != nil || params.Email == "" || params.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid request"}`))
			return
		}

		user, err := apiCfg.queries.GetUserByEmail(req.Context(), params.Email)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid email or password"}`))
		}

		err = auth.ComparePassword(user.HashedPassword, params.Password)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid email or password"}`))
			return
		}

		if params.ExpiresInSeconds == 0 || params.ExpiresInSeconds > 3600 {
			params.ExpiresInSeconds = 3600
		}

		token, err := auth.MakeJWT(user.ID, apiCfg.tokenSecret, time.Duration(params.ExpiresInSeconds)*time.Second)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
		}

		createRefreshTokenParams := database.CreateRefreshTokenParams{
			UserID:    uuid.NullUUID{UUID: user.ID, Valid: true},
			Token:     refreshToken,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
		}
		_, err = apiCfg.queries.CreateRefreshToken(req.Context(), createRefreshTokenParams)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		responseStruct := struct {
			Id           string    `json:"id"`
			CreateAt     time.Time `json:"created_at"`
			Updated_at   time.Time `json:"updated_at"`
			Email        string    `json:"email"`
			Token        string    `json:"token"`
			RefreshToken string    `json:"refresh_token"`
		}{
			Id:           user.ID.String(),
			CreateAt:     user.CreatedAt,
			Updated_at:   user.UpdatedAt,
			Email:        user.Email,
			Token:        token,
			RefreshToken: refreshToken,
		}

		response, _ := json.Marshal(&responseStruct)
		w.Write([]byte(response))

	})
	m.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerTokenFromHeader(req.Header)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized Request"}`))
			return
		}

		refreshToken, err := apiCfg.queries.GetAccessTokenFromRefreshToken(req.Context(), token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized Request"}`))
			return
		}

		token, err = auth.MakeJWT(refreshToken.UserID.UUID, apiCfg.tokenSecret, time.Hour)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		response, err := json.Marshal(map[string]string{
			"token": token,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}
		w.Write([]byte(response))
	})
	m.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerTokenFromHeader(req.Header)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized Request"}`))
			return
		}

		err = apiCfg.queries.RevokeRefreshToken(req.Context(), token)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	})

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
