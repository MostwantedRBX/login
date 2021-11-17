package storage

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

type User struct {
	// Email string `json:"email"` // Will be validating based on email so there can be multiple people with the same username, but give a unique id to each user for the display name
	Username string `json:"username"`
	Password string `json:"password"`
}

//	generate a token and send it return it
func tokenGenerator() string {
	b := make([]byte, 15)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

//	create the database with username as the key, hash and token as the rows if it doesn't exist, start it if it does
func StartDB() *sql.DB {

	db, err := sql.Open("sqlite3", "./login.db")
	if err != nil {
		log.Logger.Fatal().Err(err)
	}

	statement, err := db.Prepare("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, hash TEXT, token TEXT)")

	if err != nil {
		log.Logger.Fatal().Err(err)
	}

	_, err = statement.Exec()
	if err != nil {
		log.Logger.Fatal().Err(err)
	}

	log.Logger.Info().Msg("database opened!")
	return db
}

//	add the user, hash and generated token to the database, if the username is already there, return true, else create the use and return false.
func CreateUser(db *sql.DB, usr string, hash string) (bool, error) {

	log.Logger.Info().Msg("creating user for " + usr)
	if _, err := GetUserHash(db, usr); err == nil {
		return true, nil
	}

	statement, err := db.Prepare("INSERT INTO users (username, hash, token) VALUES (?, ?, ?)")
	if err != nil {
		return false, err
	}

	_, err = statement.Exec(usr, hash, tokenGenerator())
	if err != nil {
		return false, err
	}

	return false, nil
}

//	get the hash for the username provided, return the hash
func GetUserHash(db *sql.DB, usr string) (string, error) {

	rows, err := db.Query("SELECT username, hash FROM users")
	if err != nil {
		return "", err
	}

	var user, hash string

	for rows.Next() {
		rows.Scan(&user, &hash)
		if user == usr {
			rows.Close()
			return hash, nil
		}
	}
	rows.Close()

	return "", errors.New("could not find user in db")
}

//	get the token for the username, return token
func GetUserToken(db *sql.DB, usr string) (string, error) {

	rows, err := db.Query("SELECT username, token FROM users")
	if err != nil {
		return "", err
	}

	var user, token string

	for rows.Next() {
		rows.Scan(&user, &token)
		if user == usr {
			rows.Close()
			fmt.Println(token)
			return token, nil
		}
	}
	rows.Close()

	return "", errors.New("could not find user in db")
}

//	get username from provided token and return it
func GetUsernameFromToken(db *sql.DB, token string) (User, error) {
	rows, err := db.Query("SELECT username, token FROM users")
	if err != nil {
		return User{}, err
	}
	var user, dbToken string
	for rows.Next() {
		rows.Scan(&user, &dbToken)
		if token == dbToken {
			rows.Close()
			fmt.Println(token)
			return User{
				Username: user,
				Password: token,
			}, nil
		}
	}
	rows.Close()
	return User{}, errors.New("could not find token in db")
}
