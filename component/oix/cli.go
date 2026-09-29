package oix

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// CLI serves `mihomo oix login|account` for shell front ends such as the Asus
// Merlin plugin: one JSON object on stdin, one on stdout, and an exit status to
// branch on. Credentials stay out of argv and the environment.
const (
	ExitOK        = 0
	ExitFailed    = 1 // network, server or usage
	ExitRejected  = 2 // the panel refused the credentials or the token
	ExitThrottled = 3
)

type cliInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

type cliOutput struct {
	Token   string   `json:"token,omitempty"`
	Rebound bool     `json:"rebound,omitempty"`
	Account *Account `json:"account,omitempty"`
	Code    string   `json:"code,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func CLI(args []string, stdin io.Reader, stdout io.Writer) int {
	write := func(out cliOutput) {
		_ = json.NewEncoder(stdout).Encode(out)
	}
	if len(args) != 1 || (args[0] != "login" && args[0] != "account") {
		write(cliOutput{Code: "usage", Error: "usage: mihomo oix login|account < request.json"})
		return ExitFailed
	}
	var in cliInput
	if err := json.NewDecoder(io.LimitReader(stdin, 64<<10)).Decode(&in); err != nil {
		write(cliOutput{Code: "usage", Error: "request must be a JSON object"})
		return ExitFailed
	}

	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()
	var out cliOutput
	var err error
	switch args[0] {
	case "login":
		if strings.TrimSpace(in.Email) == "" || in.Password == "" {
			write(cliOutput{Code: "usage", Error: "email and password are required"})
			return ExitFailed
		}
		out.Token, out.Account, err = LoginWithPassword(ctx, in.Email, in.Password)
	case "account":
		token := normalizeToken(in.Token)
		if token == "" {
			write(cliOutput{Code: "usage", Error: "token is required"})
			return ExitFailed
		}
		out.Token, out.Rebound, out.Account, err = ownAccount(ctx, token)
	}
	if err != nil {
		code, status, message := describeCLIError(err)
		write(cliOutput{Code: code, Error: message})
		return status
	}
	write(out)
	return ExitOK
}

// ownAccount checks a token and, like the other official clients, trades one
// signed in by another client for this client's own, so node filters stay
// per client. Website tokens cannot be traded and keep working as they are.
func ownAccount(ctx context.Context, token string) (string, bool, *Account, error) {
	account, err := Information(ctx, token)
	if err != nil {
		return "", false, nil, err
	}
	client, _ := currentClient()
	if account.TokenClient == "" || account.TokenClient == client {
		return token, false, account, nil
	}
	rebound, err := Rebind(ctx, token)
	if err != nil {
		return token, false, account, nil
	}
	account.TokenClient = client
	return rebound, true, account, nil
}

// Transport errors are reduced to a code: their text carries the panel's address.
func describeCLIError(err error) (code string, status int, message string) {
	var panelErr *PanelError
	switch {
	case errors.Is(err, ErrRateLimited):
		code, status = "rate_limited", ExitThrottled
	case errors.As(err, &panelErr), errors.Is(err, ErrAuthFailed):
		code, status = "rejected", ExitRejected
	case errors.Is(err, ErrPanelServer):
		return "server", ExitFailed, "the oixCloud panel failed to answer"
	case errors.Is(err, ErrNoDomains):
		return "unavailable", ExitFailed, "this build has no oixCloud panel configured"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", ExitFailed, "timed out reaching the oixCloud panel"
	default:
		return "network", ExitFailed, "cannot reach the oixCloud panel"
	}
	if panelErr != nil && panelErr.Msg != "" {
		return code, status, panelErr.Msg
	}
	return code, status, err.Error()
}
