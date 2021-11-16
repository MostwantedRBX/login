package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/MostwantedRBX/login/storage"
)

var (
	db *sql.DB = storage.StartDB()
)

type (
	CookieToken struct {
		Token string `json:"token"`
	}

	UserData struct {
		Token  string `json:"token"`
		Name   string `json:"name"`
		Exists bool   `json:"exists"`
	}
)

func hashPass(raw string) (string, error) {

	hashed, err := bcrypt.GenerateFromPassword([]byte(raw), 8)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

func checkPass(usr string, pass string) (string, bool) {

	hash, err := storage.GetUserHash(db, usr)
	if err != nil {
		log.Logger.Err(err).Msg("could not get user in database")
		return "", false
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil {
		return hash, true
	}

	return "", false
}

func signIn(res http.ResponseWriter, req *http.Request) {

	var usr storage.User

	if err := json.NewDecoder(req.Body).Decode(&usr); err != nil {
		log.Logger.Debug().Err(err).Msg("could not decode json")
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	if _, ok := checkPass(strings.ToLower(usr.Username), usr.Password); ok {
		log.Logger.Info().Msg("user " + usr.Username + " logged in")

		token, err := storage.GetUserToken(db, strings.ToLower(usr.Username))
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}

		http.SetCookie(res, &http.Cookie{
			Name:     "loginToken",
			Value:    token,
			Expires:  time.Now().Add(time.Hour * 24),
			Path:     "/",
			HttpOnly: false,
		})
	} else {
		log.Logger.Info().Msg(usr.Username + " tried to log in with " + usr.Password)

		res.WriteHeader(http.StatusUnauthorized)
	}
}

func signUp(res http.ResponseWriter, req *http.Request) {

	var usr storage.User

	if err := json.NewDecoder(req.Body).Decode(&usr); err != nil {
		log.Logger.Debug().Err(err).Msg("could not decode json")
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	log.Logger.Info().Msg(usr.Username + " " + usr.Password)

	if len(usr.Password) < 4 {
		fmt.Fprintln(res, `<head><meta http-equiv="refresh" content="4; url='../create.html'" /></head> Please make sure your password has at least 4 alphanumerical characters.`)
		return
	}

	hash, err := hashPass(usr.Password)
	if err != nil {
		log.Logger.Err(err).Msg("cannot hash password for user " + usr.Username)
		return
	}

	alreadyExists, err := storage.CreateUser(db, strings.ToLower(usr.Username), hash)
	if err != nil {
		log.Logger.Err(err).Msg("user could not be added to database")
		return
	} else if alreadyExists {
		fmt.Fprintln(res, `<head><meta http-equiv="refresh" content="4; url='index.html'" /></head> That username already exists, please try another.`)
		return
	} else if !alreadyExists {
		fmt.Fprintln(res, `<head><meta http-equiv="refresh" content="0; url='index.html" /></head>`)
	}
}

func authToken(res http.ResponseWriter, req *http.Request) {

	var token CookieToken

	if err := json.NewDecoder(req.Body).Decode(&token); err != nil {
		log.Logger.Debug().Err(err).Msg("could not decode json")
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	usr, err := storage.GetUsernameFromToken(db, token.Token)
	var resp UserData
	if err != nil {
		log.Logger.Err(err).Caller()
		resp = UserData{
			Token:  token.Token,
			Name:   "",
			Exists: false,
		}
	} else {
		resp = UserData{
			Token:  token.Token,
			Name:   usr.Username,
			Exists: true,
		}
	}

	err = json.NewEncoder(res).Encode(resp)

	if err != nil {
		http.Error(res, err.Error(), 500)
		return
	}

}

func main() {

	file, err := os.OpenFile("logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.FileMode(0666))
	if err != nil {
		panic(err)
	}
	defer file.Close()

	log.Logger = log.Output(io.MultiWriter(zerolog.ConsoleWriter{Out: os.Stderr}, file))
	log.Logger.Info().Msg("Logs started")

	r := mux.NewRouter()

	r.HandleFunc("/login/", signIn).Methods("POST")
	r.HandleFunc("/signup/", signUp).Methods("POST")
	r.HandleFunc("/authtoken/", authToken).Methods("POST")
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	server := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Logger.Info().Msg("server started on localhost" + server.Addr)
	log.Logger.Fatal().Err(server.ListenAndServe()).Msg("server failed to run")
}
