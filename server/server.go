package server

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct{}

type Config struct {
	Hostname  string
	Port      string
	TLSConfig *tls.Config
}

func NewServer(config Config) (*http.Server, error) {
	router := chi.NewRouter()

	router.Use(middleware.CleanPath)
	router.Use(middleware.Heartbeat("/health"))
	router.Use(middleware.RealIP)

	// Account endpoints
	router.Post("/account/login", noopHandler)          // Your usual login
	router.Post("/account/logout", noopHandler)         // You're an idiot
	router.Post("/account/register", noopHandler)       // You're dumb
	router.Post("/account/validate-email", noopHandler) // Validate email by code send to email
	router.Get("/account/self", noopHandler)            // Get current user's account data, guard by Bearer auth
	router.Post("/account/modify-self", noopHandler)    // Modify account data

	server := &http.Server{
		Addr:              net.JoinHostPort(config.Hostname, config.Port),
		Handler:           router,
		TLSConfig:         config.TLSConfig,
		ReadTimeout:       time.Minute,
		ReadHeaderTimeout: time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Second * 30,
	}

	return server, nil
}

func noopHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusInternalServerError)
}
