package app

import "database/sql"

func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	if err := configureSQLiteConnection(db, mainSQLitePragmas...); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := executeSQLiteStatements(db, mainSQLiteSchemaStatements); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func executeSQLiteStatements(db *sql.DB, stmts []string) error {
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}
