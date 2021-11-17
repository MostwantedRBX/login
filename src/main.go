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
	//	declare db to start database from storage.go
	db *sql.DB = storage.StartDB()
)

type (
	//	declare structs for json encoding/decoding
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

	//	Generate hash from the raw password with a complexity of 8
	hashed, err := bcrypt.GenerateFromPassword([]byte(raw), 8)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

func checkPass(usr string, pass string) (string, bool) {

	// get the hash stored in the db for the username provided
	hash, err := storage.GetUserHash(db, usr)
	if err != nil {
		log.Logger.Err(err).Msg("could not get user in database")
		return "", false
	}

	//	if bcrypt doesn't return anything that means the password checks out
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil {
		//	return true because they match
		return hash, true
	}

	//	return false if the function passes over the if statement; that means that the password doesn't check out
	return "", false
}

func signIn(res http.ResponseWriter, req *http.Request) {

	var usr storage.User

	//	unpack the json request into a storage.user struct
	if err := json.NewDecoder(req.Body).Decode(&usr); err != nil {
		log.Logger.Debug().Err(err).Msg("could not decode json")
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	//	if the password checks out with checkPass(), i.e, returns true
	if _, ok := checkPass(strings.ToLower(usr.Username), usr.Password); ok {
		log.Logger.Info().Msg("user " + usr.Username + " logged in")

		//	fetch the token tied to the account
		token, err := storage.GetUserToken(db, strings.ToLower(usr.Username))
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}

		//	set the cookie in the browser to the user that logged in so we can store the session
		http.SetCookie(res, &http.Cookie{
			Name:     "loginToken",
			Value:    token,
			Expires:  time.Now().Add(time.Hour * 24),
			Path:     "/",
			HttpOnly: false,
		})
	} else {

		//	if the password does not check out, log who tried to log in and throw an unauthorized status
		log.Logger.Info().Msg(usr.Username + " tried to log in with " + usr.Password)

		res.WriteHeader(http.StatusUnauthorized)
	}
}

func signUp(res http.ResponseWriter, req *http.Request) {

	var usr storage.User

	//	decode signup info into a storage.User struct
	if err := json.NewDecoder(req.Body).Decode(&usr); err != nil {
		log.Logger.Debug().Err(err).Msg("could not decode json")
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	log.Logger.Info().Msg(usr.Username + " " + usr.Password)

	//	check that the password is at least 4 characters long
	if len(usr.Password) < 4 {
		//	TODO: Give proper feedback to user by checking the password within signup.js
		fmt.Fprintln(res, `<head><meta http-equiv="refresh" content="4; url='../create.html'" /></head> Please make sure your password has at least 4 alphanumerical characters.`)
		return
	}

	//	generate the hash for the password
	hash, err := hashPass(usr.Password)
	if err != nil {
		log.Logger.Err(err).Msg("cannot hash password for user " + usr.Username)
		return
	}

	//	try to create the user, if the user already exists alreadyExists will equal true, in which case it does not add the user.
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

	//	decode json request into CookieToken struct
	if err := json.NewDecoder(req.Body).Decode(&token); err != nil {
		log.Logger.Debug().Err(err).Msg("could not decode json")
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	//	get the user attached to the token
	usr, err := storage.GetUsernameFromToken(db, token.Token)

	//	add information into UserData struct to send back to the requester; this varies on whether or not the user exists
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

	//	encode the struct into json data
	err = json.NewEncoder(res).Encode(resp)

	if err != nil {
		http.Error(res, err.Error(), 500)
		return
	}

}

func main() {

	//	log setup
	file, err := os.OpenFile("logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.FileMode(0666))
	if err != nil {
		panic(err)
	}
	defer file.Close()

	log.Logger = log.Output(io.MultiWriter(zerolog.ConsoleWriter{Out: os.Stderr}, file))
	log.Logger.Info().Msg("Logs started")

	//	declare a new router
	r := mux.NewRouter()

	//	setup request handlers
	r.HandleFunc("/login/", signIn).Methods("POST")
	r.HandleFunc("/signup/", signUp).Methods("POST")
	r.HandleFunc("/authtoken/", authToken).Methods("POST")

	//	any requests to the path "/*" will get served with files from /static/
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	//	server settings
	server := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Logger.Info().Msg("server started on localhost" + server.Addr)
	//	listen and serve to the server information above.
	log.Logger.Fatal().Err(server.ListenAndServe()).Msg("server failed to run")
}
