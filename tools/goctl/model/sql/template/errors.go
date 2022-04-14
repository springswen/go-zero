package template

// Error defines an error template
var Error = `package {{.pkg}}

import "github.com/springswen/go-zero/core/stores/sqlx"

var ErrNotFound = sqlx.ErrNotFound
`
