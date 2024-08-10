package badgermole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/ssh"
	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"
)

type AuthorizedUser struct {
	SshPublicKey    string    `json:"-"`
	OneTimePassword string    `json:"oneTimePassword"`
	RemoteAddr      string    `json:"-"`
	Date            time.Time `json:"-"`
}

func (u *AuthorizedUser) String() string {
	return fmt.Sprintf("One Time Password: %s\n", u.OneTimePassword)
}

func (u *AuthorizedUser) Json() string {
	b, _ := json.Marshal(u)
	return string(b)
}

type IStore interface {
	AddPassForPublicKey(ctx context.Context, key ssh.PublicKey, remoteAddr string) (*AuthorizedUser, error)
}

type MemoryStore struct {
	store *sync.Map // map[PublicKey]AuthorizedUser
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		store: &sync.Map{},
	}
}

func (s *MemoryStore) AddPassForPublicKey(ctx context.Context, key ssh.PublicKey, remoteAddr string) (*AuthorizedUser, error) {
	authorizedKey := gossh.MarshalAuthorizedKey(key)
	cleanedKey := strings.Replace(string(authorizedKey), "\n", "", -1)
	pass := uuid.NewString()
	user := &AuthorizedUser{
		SshPublicKey:    cleanedKey,
		OneTimePassword: pass,
		Date:            time.Now(),
		RemoteAddr:      remoteAddr,
	}
	s.store.Store(cleanedKey, user)

	return user, nil
}

func (s *MemoryStore) OneTimePasswordExists(ctx context.Context, pass string) bool {
	isFound := false
	s.store.Range(func(key, value any) bool {
		user := value.(*AuthorizedUser)
		if user.OneTimePassword == pass {
			isFound = true
			return false
		}
		return true
	})

	return isFound
}

func (s *MemoryStore) GetUserFromOtp(ctx context.Context, otp string) (*AuthorizedUser, error) {
	var foundUser *AuthorizedUser
	s.store.Range(func(key, value any) bool {
		user := value.(*AuthorizedUser)
		if user.OneTimePassword == otp {
			foundUser = user
			return false
		}
		return true
	})
	if foundUser == nil {
		return nil, errors.New("not found")
	}

	return foundUser, nil
}

func (s *MemoryStore) RemoveOtp(ctx context.Context, pk string) {
	s.store.Delete(pk)
}

func (s *MemoryStore) RunCleanScheduler(ctx context.Context, dur time.Duration) {
	ticker := time.NewTicker(dur)
	for {
		select {
		case <-ticker.C:
			s.store.Range(func(key, value any) bool {
				user := value.(*AuthorizedUser)
				if time.Since(user.Date) >= dur {
					s.store.Delete(key)
				}
				return true
			})

		case <-ctx.Done():
			return
		}
	}
}
