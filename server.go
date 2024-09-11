package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"medods/token"

	"github.com/jackc/pgx/v5"
)

type Config struct {
	DB struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		DBName   string `json:"dbname"`
	} `json:"db"`
}

func main() {
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Error opening config file: %v\n", err)
	}
	defer file.Close()

	var config Config
	err = json.NewDecoder(file).Decode(&config)
	if err != nil {
		log.Fatalf("Error decoding config file: %v\n", err)
	}

	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		config.DB.User, config.DB.Password, config.DB.Host, config.DB.Port, config.DB.DBName)

	conn, err := pgx.Connect(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer conn.Close(context.Background())

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		token.GiveTokens(w, r, conn)
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		token.RefreshTokens(w, r, conn)
	})

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
