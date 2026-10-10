// Planted: a request value formatted into SQL.
package store

import (
	"database/sql"
	"fmt"
	"net/http"
)

func FindUser(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	name := r.URL.Query().Get("name")
	return db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
}
