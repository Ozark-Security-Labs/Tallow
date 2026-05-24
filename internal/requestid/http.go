package requestid

import "net/http"

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(Header)
		if !Valid(id) {
			id = New()
		}
		w.Header().Set(Header, id)
		next.ServeHTTP(w, r.WithContext(WithContext(r.Context(), id)))
	})
}
