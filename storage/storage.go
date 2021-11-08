package storage

import (
	"database/sql"
	"errors"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

func StartDB() *sql.DB {

	db, err := sql.Open("sqlite3", "./login.db")
	if err != nil {
		log.Logger.Fatal().Err(err)
	}

	statement, err := db.Prepare("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, hash TEXT)")

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

func CreateUser(db *sql.DB, usr string, hash string) (bool, error) {

	log.Logger.Info().Msg("creating user for " + usr)
	if _, err := GetUserHash(db, usr); err == nil {
		return true, nil
	}

	statement, err := db.Prepare("INSERT INTO users (username, hash) VALUES (?, ?)")
	if err != nil {
		return false, err
	}

	_, err = statement.Exec(usr, hash)
	if err != nil {
		return false, err
	}

	return false, nil
}

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
