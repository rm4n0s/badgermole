package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rm4n0s/badgermole"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var (
		webhost string
		sshhost string
		keypath string
	)
	flag.StringVar(&webhost, "webhost", "localhost:3000", "ip:port of the website")
	flag.StringVar(&sshhost, "sshhost", "localhost:10000", "ip:port of the ssh OTP")
	flag.StringVar(&keypath, "keypath", ".ssh/id_ed25519", "the path of the private key file path for the SSH OTP app")
	flag.Parse()
	otpStore := badgermole.NewMemoryStore()
	mux := http.NewServeMux()
	handlers := NewHandlers(otpStore)
	cfg := &badgermole.Config{
		SshHost:     sshhost,
		SshKeyPath:  keypath,
		SshAuthFunc: handlers.sshAuthHandler,
		Store:       otpStore,
	}
	bmSrv, err := badgermole.NewServer(cfg)
	if err != nil {
		log.Fatal("Error:", err)
	}
	mux.HandleFunc("GET /", handlers.getHomeHandler)
	mux.HandleFunc("GET /signup", handlers.getSignUpHandler)
	mux.HandleFunc("POST /signup", handlers.postSignUpHandler)
	mux.HandleFunc("GET /login", handlers.getLoginHandler)
	mux.HandleFunc("POST /login", handlers.postLoginHandler)
	mux.HandleFunc("GET /users", handlers.getUsersHandler)
	mux.HandleFunc("GET /profile", handlers.getProfileHandler)
	mux.HandleFunc("GET /logout", handlers.getLogoutHandler)

	httpSrv := &http.Server{
		Addr:    webhost,
		Handler: mux,
	}
	log.Println("Web server:", webhost)
	log.Println("OTP server:", sshhost)

	go func(bmSrv *badgermole.Server) {
		err := bmSrv.Start()
		if err != nil {
			log.Println("Error:", err)
		}
	}(bmSrv)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// clean OTP that lasted a minute
	go otpStore.RunCleanScheduler(ctx, 1*time.Minute)

	go func(ctx context.Context) {
		<-ctx.Done()
		bmSrv.Stop(ctx)
		httpSrv.Shutdown(ctx)
		log.Println("bye!")
	}(ctx)

	httpSrv.ListenAndServe()
}
