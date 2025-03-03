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
	"sort"
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
	polkaApiKey    string
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
	polkaApiKey := os.Getenv("POLKA_API_KEY")

	db, _ := sql.Open("postgres", dbUrl)
	dbQueries := database.New(db)

	apiCfg.queries = dbQueries
	apiCfg.platform = platform
	apiCfg.tokenSecret = tokenSecret
	apiCfg.polkaApiKey = polkaApiKey

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
	m.HandleFunc("DELETE /api/chirps/{chirpID}", func(w http.ResponseWriter, req *http.Request) {
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

		if chirp.UserID.UUID != userID {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Forbidden"}`))
			return
		}

		err = apiCfg.queries.DeleteChirp(req.Context(), chirpUUID)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	})
	m.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		type chirpResponse struct {
			Id         string    `json:"id"`
			CreateAt   time.Time `json:"created_at"`
			Updated_at time.Time `json:"updated_at"`
			Body       string    `json:"body"`
			UserId     string    `json:"user_id"`
		}

		userID := req.URL.Query().Get("author_id")
		sortBy := req.URL.Query().Get("sort")

		if sortBy != "asc" && sortBy != "desc" {
			sortBy = "asc"
		}

		if userID != "" {
			parsedUserID, err := uuid.Parse(userID)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Write([]byte(`{"error": "Invalid user ID"}`))
				return
			}

			chirps, err := apiCfg.queries.SelectChirpsByUserId(req.Context(), uuid.NullUUID{UUID: parsedUserID, Valid: true})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					w.WriteHeader(http.StatusNotFound)
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.Write([]byte(`User has no chirps`))
					return
				}

				w.WriteHeader(http.StatusNotFound)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Write([]byte(`User not found`))
			}

			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")

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

			sort.Slice(response, func(i, j int) bool {
				if sortBy == "asc" {
					return response[i].CreateAt.Before(response[j].CreateAt)
				}
				return response[i].CreateAt.After(response[j].CreateAt)
			})

			responseJSON, _ := json.Marshal(&response)
			w.Write([]byte(responseJSON))
			return
		}

		chirps, err := apiCfg.queries.SelectChirps(req.Context())

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

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

		sort.Slice(response, func(i, j int) bool {
			if sortBy == "asc" {
				return response[i].CreateAt.Before(response[j].CreateAt)
			}
			return response[i].CreateAt.After(response[j].CreateAt)
		})

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
			Id          string    `json:"id"`
			CreateAt    time.Time `json:"created_at"`
			Updated_at  time.Time `json:"updated_at"`
			Email       string    `json:"email"`
			IsChirpyRed bool      `json:"is_chirpy_red"`
		}

		response := make([]userResponse, len(users))

		for i, user := range users {
			response[i] = userResponse{
				Id:          user.ID.String(),
				CreateAt:    user.CreatedAt,
				Updated_at:  user.UpdatedAt,
				Email:       user.Email,
				IsChirpyRed: user.IsChirpyRed,
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
			Id          string    `json:"id"`
			CreateAt    time.Time `json:"created_at"`
			Updated_at  time.Time `json:"updated_at"`
			Email       string    `json:"email"`
			IsChirpyRed bool      `json:"is_chirpy_red"`
		}{
			Id:          user.ID.String(),
			CreateAt:    user.CreatedAt,
			Updated_at:  user.UpdatedAt,
			Email:       user.Email,
			IsChirpyRed: user.IsChirpyRed,
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
			Id          string    `json:"id"`
			CreateAt    time.Time `json:"created_at"`
			Updated_at  time.Time `json:"updated_at"`
			Email       string    `json:"email"`
			IsChirpyRed bool      `json:"is_chirpy_red"`
		}{
			Id:          user.ID.String(),
			CreateAt:    user.CreatedAt,
			Updated_at:  user.UpdatedAt,
			Email:       user.Email,
			IsChirpyRed: user.IsChirpyRed,
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
			IsChirpyRed  bool      `json:"is_chirpy_red"`
		}{
			Id:           user.ID.String(),
			CreateAt:     user.CreatedAt,
			Updated_at:   user.UpdatedAt,
			Email:        user.Email,
			Token:        token,
			RefreshToken: refreshToken,
			IsChirpyRed:  user.IsChirpyRed,
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
	m.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetApiTokenFromHeader(req.Header)
		fmt.Printf("TOKEN: %s\n", token)

		if err != nil || token != apiCfg.polkaApiKey {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Unauthorized Request"}`))
			return
		}

		type data struct {
			UserId string `json:"user_id"`
		}
		type webhookParams struct {
			Event string `json:"event"`
			Data  data   `json:"data"`
		}

		var params webhookParams
		decoder := json.NewDecoder(req.Body)
		err = decoder.Decode(&params)

		if err != nil || params.Event == "" || params.Data.UserId == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid request"}`))
			return
		}

		if params.Event != "user.upgraded" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		userID, err := uuid.Parse(params.Data.UserId)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Invalid user id"}`))
			return
		}

		userInfo := database.UpdateUserIsChirpyRedParams{
			IsChirpyRed: true,
			ID:          userID,
		}

		user, err := apiCfg.queries.UpdateUserIsChirpyRed(req.Context(), userInfo)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "Internal server error"}`))
			return
		}

		if user.ID == uuid.Nil {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Write([]byte(`{"error": "User not found"}`))
			return
		}

		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(``))
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
