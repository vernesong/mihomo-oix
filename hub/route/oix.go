package route

import (
	"errors"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/component/oix"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// Serialize account and options mutations through their configuration reload.
var oixMutationMu sync.Mutex

func oixRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/login", oixLogin)
	r.Post("/logout", oixLogout)
	r.Get("/options", oixGetOptions)
	r.Put("/options", oixSetOptions)
	r.Delete("/options", oixResetOptions)
	return r
}

func oixGetOptions(w http.ResponseWriter, r *http.Request) {
	state, err := oix.GetParamsState(C.Path.HomeDir())
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.JSON(w, r, state)
}

func oixSetOptions(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Params *string `json:"params"`
	}{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if req.Params == nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("params is required"))
		return
	}
	oixMutationMu.Lock()
	defer oixMutationMu.Unlock()

	if err := oix.SetParams(C.Path.HomeDir(), *req.Params); err != nil {
		render.Status(r, oixOptionsErrorStatus(err))
		render.JSON(w, r, newError(err.Error()))
		return
	}
	if err := reloadoixOptions(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	oixGetOptions(w, r)
}

func oixResetOptions(w http.ResponseWriter, r *http.Request) {
	oixMutationMu.Lock()
	defer oixMutationMu.Unlock()

	if err := oix.ResetParams(C.Path.HomeDir()); err != nil {
		render.Status(r, oixOptionsErrorStatus(err))
		render.JSON(w, r, newError(err.Error()))
		return
	}
	if err := reloadoixOptions(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	oixGetOptions(w, r)
}

func oixOptionsErrorStatus(err error) int {
	switch {
	case errors.Is(err, oix.ErrParamsTooLong), errors.Is(err, oix.ErrParamsInvalid):
		return http.StatusBadRequest
	case errors.Is(err, oix.ErrParamsEnvironmentOverride):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// reloadConfig re-reads the configuration file so an account or options change
// takes effect, including the providers it selects.
func reloadConfig() error {
	cfg, err := executor.ParseWithPath(C.Path.Config())
	if err != nil {
		return err
	}
	executor.ApplyConfig(cfg, false)
	return nil
}

func reloadoixOptions() error {
	if !oix.HasToken() {
		return nil
	}
	if err := oix.ForceUpdate(); err != nil {
		return err
	}
	if provider, exists := tunnel.Providers()[oix.ProviderFile()]; exists {
		return provider.Update()
	}
	return reloadConfig()
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

	if err := reloadConfig(); err != nil {
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

	if err := reloadConfig(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	render.NoContent(w, r)
}
