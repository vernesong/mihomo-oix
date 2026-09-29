package oix

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// CLI serves `mihomo oix login|account` for shell front ends such as the Asus
// Merlin plugin: one JSON object on stdin, one on stdout, and an exit status to
// branch on. Credentials stay out of argv and the environment.
const (
	exitOK        = 0
	exitFailed    = 1 // network, server or usage
	exitRejected  = 2 // the panel refused the credentials or the token
	exitThrottled = 3
)

type cliInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

type cliOutput struct {
	Token   string       `json:"token,omitempty"`
	Rebound bool         `json:"rebound,omitempty"`
	Account *accountInfo `json:"account,omitempty"`
	Code    string       `json:"code,omitempty"`
	Error   string       `json:"error,omitempty"`
}

func CLI(args []string, stdin io.Reader, stdout io.Writer) int {
	format := "json"
	write := func(out cliOutput) {
		if format == "lines" {
			writeLines(stdout, out)
			return
		}
		_ = json.NewEncoder(stdout).Encode(out)
	}
	usage := cliOutput{Code: "usage", Error: "usage: mihomo oix login|account [-format json|lines] < request.json"}
	if len(args) == 0 || (args[0] != "login" && args[0] != "account") {
		write(usage)
		return exitFailed
	}
	flags := flag.NewFlagSet("oix "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&format, "format", "json", "")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || (format != "json" && format != "lines") {
		format = "json"
		write(usage)
		return exitFailed
	}
	// the flags that validate it for the core are not parsed for subcommands
	if id := os.Getenv("OIX_CLIENT"); id != "" {
		if err := SetClient(id); err != nil {
			write(cliOutput{Code: "usage", Error: err.Error()})
			return exitFailed
		}
	}
	var in cliInput
	if err := json.NewDecoder(io.LimitReader(stdin, 64<<10)).Decode(&in); err != nil {
		write(cliOutput{Code: "usage", Error: "request must be a JSON object"})
		return exitFailed
	}

	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()
	var out cliOutput
	var err error
	switch args[0] {
	case "login":
		if strings.TrimSpace(in.Email) == "" || in.Password == "" {
			write(cliOutput{Code: "usage", Error: "email and password are required"})
			return exitFailed
		}
		out.Token, out.Account, err = loginWithPassword(ctx, in.Email, in.Password)
	case "account":
		token := normalizeToken(in.Token)
		if token == "" {
			write(cliOutput{Code: "usage", Error: "token is required"})
			return exitFailed
		}
		out.Token, out.Rebound, out.Account, err = ownAccount(ctx, token)
	}
	if err != nil {
		code, status, message := describeCLIError(err)
		write(cliOutput{Code: code, Error: message})
		return status
	}
	write(out)
	return exitOK
}

// ownAccount checks a token and, like the other official clients, trades one
// signed in by another client for this client's own, so node filters stay
// per client. Website tokens cannot be traded and keep working as they are.
func ownAccount(ctx context.Context, token string) (string, bool, *accountInfo, error) {
	account, err := accountInformation(ctx, token)
	if err != nil {
		return "", false, nil, err
	}
	client, _ := currentClient()
	if account.TokenClient == "" || account.TokenClient == client {
		return token, false, account, nil
	}
	rebound, err := rebindToken(ctx, token)
	if err != nil {
		return token, false, account, nil
	}
	account.TokenClient = client
	return rebound, true, account, nil
}

// Transport errors are reduced to a code: their text carries the panel's address.
func describeCLIError(err error) (code string, status int, message string) {
	var panelErr *panelError
	switch {
	case errors.Is(err, errRateLimited):
		code, status = "rate_limited", exitThrottled
	case errors.As(err, &panelErr), errors.Is(err, ErrAuthFailed):
		code, status = "rejected", exitRejected
	case errors.Is(err, errPanelServer):
		return "server", exitFailed, "the oixCloud panel failed to answer"
	case errors.Is(err, ErrNoDomains):
		return "unavailable", exitFailed, "this build has no oixCloud panel configured"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", exitFailed, "timed out reaching the oixCloud panel"
	default:
		return "network", exitFailed, "cannot reach the oixCloud panel"
	}
	if panelErr != nil && panelErr.Msg != "" {
		return code, status, panelErr.Msg
	}
	return code, status, err.Error()
}

// writeLines prints key=value lines for shells without a JSON parser; values
// never span lines, so `sed -n 's/^token=//p'` reads them without eval.
func writeLines(w io.Writer, out cliOutput) {
	line := func(key, value string) {
		if value != "" {
			value = strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
			_, _ = fmt.Fprintf(w, "%s=%s\n", key, value)
		}
	}
	line("token", out.Token)
	if out.Rebound {
		line("rebound", "1")
	}
	if a := out.Account; a != nil {
		line("plan", a.Plan)
		line("plan_time", a.PlanTime)
		line("plan_rank", strconv.Itoa(a.PlanRank))
		line("used", a.Used)
		line("traffic", a.Traffic)
		line("unused", a.Unused)
		line("today_used", a.TodayUsed)
		line("token_client", a.TokenClient)
	}
	line("code", out.Code)
	line("error", out.Error)
}
