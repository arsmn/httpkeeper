# arsmn/httpkeeper

`httpkeeper` currently provides HTTP External Authentication Service middleware for Go. It is compatible with Go's own `net/http`, goji, Gin & anything that implements the `http.Handler` interface.

### Install It

```sh
$ go get github.com/arsmn/httpkeeper
```

#### Advanced Usage

`httpkeeper` provides a `ExternalAuth` function to get you up and running.
You should pass a `ExternalKeeperOptions` struct to `ExternalAuth`. `NewExternalKeeperOptions` provides a `ExternalKeeperOptions` with default values.

For more control over the process, use `With` prefixed functions. This allows you to:

* Configure ‍‍`AllowedRequestHeaders` lists headers that will be sent from the client to the auth service.
* Provide your own `NotFoundHandler`, `UnauthorizedHandler`, `ForbiddenHandler`, `InternalServerErrorHandler` (anything that satisfies `http.Handler`) so you can return a better response.
* Configure `IncludeBody` to send request body to auth service.

### gorilla/mux

Since it's all `http.Handler`, `httpauth` works with [gorilla/mux](https://github.com/gorilla/mux) (and most other routers) as well:

```go
package main

import (
	"net/http"

	"github.com/arsmn/httpkeeper"
	"github.com/gorilla/mux"
)

func main() {
    opts := httpkeeper.NewExternalKeeperOptions("127.0.0.1:8080", "external", "http")

	r := mux.NewRouter()

	r.HandleFunc("/", YourHandler)
	http.Handle("/", httpkeeper.ExternalAuth(opts)(r))

	http.ListenAndServe(":7000", nil)
}

func YourHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Gorilla!\n"))
}
```

### net/http

If you're using vanilla `net/http`:

```go
package main

import(
	"net/http"

	"github.com/arsmn/httpkeeper"
)

func main() {
    opts := httpkeeper.NewExternalKeeperOptions("127.0.0.1:8080", "external", "http")
	http.Handle("/", httpkeeper.ExternalAuth(opts)(http.HandlerFunc(YourHandler)))
	http.ListenAndServe(":7000", nil)
}
```

## Contributing

Feel free to send pull requests and open issues!

## License

MIT Licensed. See the LICENSE file for details.
