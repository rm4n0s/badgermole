package badgermole

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/logging"
)

type Config struct {
	SshHost     string
	SshKeyPath  string
	SshAuthFunc func(ctx ssh.Context, key ssh.PublicKey) bool
	Store       IStore
}

type Server struct {
	srv   *ssh.Server
	store IStore
}

func NewServer(config *Config) (*Server, error) {
	if config.Store == nil {
		return nil, errors.New("store is nil")
	}
	srv, err := wish.NewServer(
		wish.WithAddress(config.SshHost),
		wish.WithHostKeyPath(config.SshKeyPath),
		wish.WithPublicKeyAuth(config.SshAuthFunc),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create an SSH server: %w", err)
	}
	mole := &Server{
		srv:   srv,
		store: config.Store,
	}

	err = mole.srv.SetOption(wish.WithMiddleware(
		mole.sshHandler,
		logging.Middleware(),
	))

	if err != nil {
		return nil, fmt.Errorf("failed to set SSH middleware: %w", err)
	}
	return mole, nil
}

func (s *Server) sshHandler(next ssh.Handler) ssh.Handler {
	return func(sess ssh.Session) {
		u, err := s.store.AddPassForPublicKey(sess.Context(), sess.PublicKey(), sess.RemoteAddr().String())
		if err != nil {
			wish.Println(sess, "Error: "+err.Error())
			next(sess)
			return
		}
		if slices.Contains(sess.Command(), "json") {
			wish.Println(sess, u.Json())
			next(sess)
			return
		}
		wish.Println(sess, u.String())
		next(sess)
	}
}

func (s *Server) Start() error {
	err := s.srv.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to serve SSH server: %w", err)
	}
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	err := s.srv.Shutdown(ctx)
	if err != nil {
		return fmt.Errorf("failed to stop SSH server: %w", err)
	}
	return nil
}
