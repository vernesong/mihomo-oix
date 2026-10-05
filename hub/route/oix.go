package route

import (
	"strings"
	"sync"

	"github.com/metacubex/mihomo/component/oix"
	"github.com/metacubex/mihomo/hub/executor"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// Serialize account mutations through their configuration reload.
var oixMutationMu sync.Mutex

func oixRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/login", oixLogin)
	r.Post("/logout", oixLogout)
	r.Get("/profile/dns", oixProfileDNS)
	return r
}

func oixProfileDNS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	dns, ok := oix.GetProfileDNS()
	if !ok {
		render.Status(r, http.StatusConflict)
		render.JSON(w, r, newError("managed profile DNS is not available"))
		return
	}
	render.JSON(w, r, dns)
}

func oixLogin(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Token string `json:"token"`
	}{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if strings.TrimSpace(req.Token) == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("token is required"))
		return
	}

	oixMutationMu.Lock()
	defer oixMutationMu.Unlock()

	ok, err := oix.Login(req.Token)
	if err != nil {
		status := http.StatusServiceUnavailable
		if oix.IsAuthError(err) {
			status = http.StatusUnauthorized
		}
		render.Status(r, status)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	if !ok {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError(oix.ErrNoSubscription.Error()))
		return
	}

	if err := executor.ReloadConfig(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	render.NoContent(w, r)
}

func oixLogout(w http.ResponseWriter, r *http.Request) {
	oixMutationMu.Lock()
	defer oixMutationMu.Unlock()

	oix.Logout()

	if err := executor.ReloadConfig(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	render.NoContent(w, r)
}
