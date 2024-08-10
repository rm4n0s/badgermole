package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/charmbracelet/ssh"
	"github.com/rm4n0s/badgermole"
	gossh "golang.org/x/crypto/ssh"
)

type Name string
type SshKey string

type Handlers struct {
	users     map[SshKey]Name
	userMutex *sync.RWMutex
	tmpl      *Template
	otpStore  *badgermole.MemoryStore
}

func NewHandlers(otpStore *badgermole.MemoryStore) *Handlers {
	return &Handlers{
		users:     map[SshKey]Name{},
		tmpl:      NewTemplate(),
		otpStore:  otpStore,
		userMutex: &sync.RWMutex{},
	}
}
func (h *Handlers) sshAuthHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	authorizedKey := gossh.MarshalAuthorizedKey(key)
	cleanedKey := strings.Replace(string(authorizedKey), "\n", "", -1)
	h.userMutex.RLock()
	defer h.userMutex.RUnlock()
	name, ok := h.users[SshKey(cleanedKey)]
	if ok {
		log.Println(name, "passed SSH authentication")
		return true
	}

	return false
}

func (h *Handlers) getHomeHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("authorized")
	authorized := err == nil

	h.tmpl.Render(w, "home.html", authorized)
}

func (h *Handlers) getSignUpHandler(w http.ResponseWriter, r *http.Request) {
	h.tmpl.Render(w, "signup.html", nil)
}

func (h *Handlers) postSignUpHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	pk := r.FormValue("publickey")
	log.Println("New user signed up and the name is", name, "with public key", pk)
	if len(name) == 0 {
		h.tmpl.Render(w, "error", "name is empty")
		return
	}
	if len(pk) == 0 {
		h.tmpl.Render(w, "error", "public key is empty")
		return
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(
		[]byte(pk),
	)
	if err != nil {
		h.tmpl.Render(w, "error", fmt.Sprint("public key error:", err.Error()))
		return
	}
	authorizedKey := gossh.MarshalAuthorizedKey(parsed)
	cleanedKey := strings.Replace(string(authorizedKey), "\n", "", -1)
	h.userMutex.Lock()
	h.users[SshKey(cleanedKey)] = Name(name)
	h.userMutex.Unlock()

	h.tmpl.Render(w, "signup-success", nil)
}

func (h *Handlers) getLoginHandler(w http.ResponseWriter, r *http.Request) {
	h.tmpl.Render(w, "login.html", nil)
}

func (h *Handlers) postLoginHandler(w http.ResponseWriter, r *http.Request) {
	otp := r.FormValue("otp")
	if len(otp) == 0 {
		h.tmpl.Render(w, "not-correct-otp", nil)
		return
	}
	au, err := h.otpStore.GetUserFromOtp(r.Context(), otp)
	if err != nil {
		h.tmpl.Render(w, "not-correct-otp", nil)
		return
	}
	h.userMutex.RLock()
	defer h.userMutex.RUnlock()
	name, ok := h.users[SshKey(au.SshPublicKey)]
	if !ok {
		h.tmpl.Render(w, "error", "user does not exist anymore")
		return
	}
	cookie := http.Cookie{
		Name:     "authorized",
		Value:    string(name),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	h.otpStore.RemoveOtp(r.Context(), au.SshPublicKey)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handlers) getUsersHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("authorized")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			h.tmpl.Render(w, "unauthorized.html", nil)
		default:
			log.Println("Error:", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	h.userMutex.RLock()
	defer h.userMutex.RUnlock()
	h.tmpl.Render(w, "users.html", h.users)
}

func (h *Handlers) getProfileHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("authorized")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			h.tmpl.Render(w, "unauthorized.html", nil)
		default:
			log.Println("Error:", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	name := Name(cookie.Value)
	var key SshKey
	h.userMutex.RLock()
	defer h.userMutex.RUnlock()
	for k, v := range h.users {
		if v == name {
			key = k
			break
		}
	}

	user := struct {
		Name string
		Key  string
	}{
		Name: string(name),
		Key:  string(key),
	}

	h.tmpl.Render(w, "profile.html", user)
}

func (h *Handlers) getLogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("authorized")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			h.tmpl.Render(w, "unauthorized.html", nil)
		default:
			log.Println("Error:", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
