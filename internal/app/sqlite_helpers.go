package app

import "database/sql"

func configureSQLiteConnection(db *sql.DB, pragmas ...string) error {
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return err
		}
	}

	return nil
}
