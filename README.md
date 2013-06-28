## Intro
Not production ready!!!
Implements postgresql protocol, does not use any library.
Nonblocking via [lua-nginx-module](https://github.com/chaoslawful/lua-nginx-module)'s socket api.

## Example
````lua
local pg = require("pg")
local db = pg.connect("unix:/run/postgresql/.s.PGSQL.5432", "user", "db")
for k,v in pairs(db:query("SELECT * FROM test;")) do
	print(v.column)
end
db:disconnect()
````

## API

##### `connect(host,user,db,port)`
Returns a new db object

##### `db:query(query)`
Runs a query against `db` and returns result as table

##### `db:prepare(name,query)`
Creates a prepared query named `name`

##### `db:execute(name)`
Runs prepared query `name`

##### `db:disconnect()`
Disconnects from db, but pools the connection via `sock:setkeepalive()`
