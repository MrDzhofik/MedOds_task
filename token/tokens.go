package token

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("CristianoRonaldo")

type TokenRequest struct {
	JWTToken     string `json:"json_web_token"`
	RefreshToken string `json:"refresh_token"`
}

func generateJWT(userId, ip string) (string, error) {
	expires := time.Now().Add(time.Minute * 15)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID":  userId,
		"ip":      ip,
		"expires": expires.Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)

	return tokenString, err
}

func generateRT() (string, error) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}

	refreshToken := base64.URLEncoding.EncodeToString(tokenBytes)

	return refreshToken, nil
}

func saveRT(db *pgx.Conn, userID, refreshToken, ip string) error {
	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Exec(context.Background(), "INSERT INTO refresh_tokens(user_id, refresh_token_hash, ip_address) VALUES ($1, $2, $3)", userID, refreshTokenHash, ip)
	if err != nil {
		return err
	}

	return nil
}

func getIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return ip
}

func GiveTokens(w http.ResponseWriter, r *http.Request, db *pgx.Conn) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "Необходим идентификатор пользователя", http.StatusBadRequest)
		return
	}

	ip := getIP(r)

	jwt, err := generateJWT(userID, ip)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Ошибка при создании JWT токена", http.StatusInternalServerError)
		return
	}

	rt, err := generateRT()
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Ошибка при создании RT токена", http.StatusInternalServerError)
		return
	}

	err = saveRT(db, userID, rt, ip)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Ошибка при добавлении RT токена", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"json_web_token": jwt,
		"refresh_token":  rt,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func RefreshTokens(w http.ResponseWriter, r *http.Request, db *pgx.Conn) {
	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неправильный запрос", http.StatusBadRequest)
		return
	}
	// проверка JWT подписи
	token, err := jwt.Parse(req.JWTToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("подделка JWT")
		}

		return jwtSecret, nil
	})

	if err != nil {
		http.Error(w, "Неправильный токен!", http.StatusUnauthorized)
		return
	}

	var userID string
	var ip string

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userID = claims["userID"].(string)
		ip = claims["ip"].(string)
	} else {
		http.Error(w, "Ошибка в теле токена", http.StatusInternalServerError)
		return
	}

	currentIP := getIP(r)

	// проверка IP
	if ip != currentIP {
		// email warning (доделать)
		http.Error(w, "IP не совпадает!", http.StatusUnauthorized)
		return
	}

	// проверка RT
	var storedHash string
	err = db.QueryRow(context.Background(),
		"SELECT refresh_token_hash FROM refresh_tokens WHERE user_id=$1 AND ip_address=$2 ORDER BY created_at DESC LIMIT 1",
		userID, ip).Scan(&storedHash)

	if err != nil {
		http.Error(w, "Неправильный RT", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.RefreshToken))
	if err != nil {
		http.Error(w, "Подделка RT!", http.StatusUnauthorized)
		return
	}

	// генерируем новые токены
	newJWT, err := generateJWT(userID, ip)
	if err != nil {
		http.Error(w, "Ошибка создания нового JWT", http.StatusInternalServerError)
		return
	}

	newRT, err := generateRT()
	if err != nil {
		http.Error(w, "Ошибка создания нового RY", http.StatusInternalServerError)
		return
	}

	// записываем в базу
	err = saveRT(db, userID, newRT, ip)
	if err != nil {
		http.Error(w, "Ошибка записи в базу нового RT", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token":  newJWT,
		"refresh_token": newRT,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
