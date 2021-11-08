package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/MostwantedRBX/login/storage"
)

var db *sql.DB = storage.StartDB()

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

	u, err := url.Parse(req.URL.String())
	if err != nil {
		log.Logger.Err(err).Caller().Msg("could not parse url")
		return
	}

	var usr, pass string = u.Query().Get("uname"), u.Query().Get("pass")

	if hash, ok := checkPass(strings.ToLower(usr), pass); ok {
		log.Logger.Info().Msg("user " + usr + " logged in")
		fmt.Fprint(res, `
		Logged In
		Username: `+usr+`
		Password: `+pass+`
		Hash: `+hash)
	}
}

func signUp(res http.ResponseWriter, req *http.Request) {

	u, err := url.Parse(req.URL.String())
	if err != nil {
		log.Logger.Err(err)
		return
	}

	var usr, pass string = u.Query().Get("uname"), u.Query().Get("pass")

	if len(pass) < 4 {
		fmt.Fprintln(res, `<head><meta http-equiv="refresh" content="4; url='../create.html'" /></head> Please make sure your password has at least 4 alphanumerical characters.`)
		return
	}

	hash, err := hashPass(pass)
	if err != nil {
		log.Logger.Err(err).Msg("cannot hash password for user " + usr)
		return
	}

	alreadyExists, err := storage.CreateUser(db, strings.ToLower(usr), hash)
	if err != nil {
		log.Logger.Err(err).Msg("user could not be added to database")
		return
	} else if alreadyExists {
		fmt.Fprintln(res, `<head><meta http-equiv="refresh" content="4; url='../create.html'" /></head> That username already exists, please try another.`)
		return
	} else if !alreadyExists {
		fmt.Fprintln(res, `<head><meta http-equiv="refresh" content="0; url='../login.html'" /></head>`)
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

	r.HandleFunc("/pages/login/signin", signIn)
	r.HandleFunc("/pages/create/signup", signUp)
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
