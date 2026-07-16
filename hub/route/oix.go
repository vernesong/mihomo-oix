package route

import (
	"errors"
	"strings"

	"github.com/metacubex/mihomo/component/oix"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

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
	if err := oix.SetParams(C.Path.HomeDir(), *req.Params); err != nil {
		render.Status(r, oixOptionsErrorStatus(err))
		render.JSON(w, r, newError(err.Error()))
		return
	}
	if err := reloadOixOptions(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	oixGetOptions(w, r)
}

func oixResetOptions(w http.ResponseWriter, r *http.Request) {
	if err := oix.ResetParams(C.Path.HomeDir()); err != nil {
		render.Status(r, oixOptionsErrorStatus(err))
		render.JSON(w, r, newError(err.Error()))
		return
	}
	if err := reloadOixOptions(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	oixGetOptions(w, r)
}

func oixOptionsErrorStatus(err error) int {
	switch {
	case errors.Is(err, oix.ErrParamsTooLong):
		return http.StatusBadRequest
	case errors.Is(err, oix.ErrParamsEnvironmentOverride):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func reloadOixOptions() error {
	if !oix.HasToken() {
		return nil
	}
	if err := oix.ForceUpdate(); err != nil {
		return err
	}
	if provider, exists := tunnel.Providers()[oix.ProviderFile()]; exists {
		return provider.Update()
	}
	cfg, err := executor.ParseWithPath(C.Path.Config())
	if err != nil {
		return err
	}
	executor.ApplyConfig(cfg, false)
	return nil
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
		render.JSON(w, r, newError("no subscription found for this token"))
		return
	}

	cfg, err := executor.ParseWithPath(C.Path.Config())
	if err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	executor.ApplyConfig(cfg, false)

	render.NoContent(w, r)
}

func oixLogout(w http.ResponseWriter, r *http.Request) {
	oix.Logout()

	cfg, err := executor.ParseWithPath(C.Path.Config())
	if err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	executor.ApplyConfig(cfg, false)

	render.NoContent(w, r)
}
