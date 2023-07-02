package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"lado.one/auth/mockDB"
)

// Login function. Serve login page, and check if already logged in
func login(w http.ResponseWriter, r *http.Request) {
	// Get session cookie
	cookie, err := r.Cookie("session")

	if err != nil {
		if err == http.ErrNoCookie {
			http.ServeFile(w, r, "app/login.html")
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check session cookie
	_, err = mockDB.Get("mockDB/sessions.txt", cookie.Value)
	if err == nil {
		http.Redirect(w, r, "/app", http.StatusFound)
		return
	}

	// Serve login page (could not validate session cookie)
	http.ServeFile(w, r, "app/login.html")
}

// Authenticate function. Get credentials from a POST request and issues a session cookie
func authenticate(w http.ResponseWriter, r *http.Request) {
	// Get credentials from POST request
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Check credentials
	salt, _ := mockDB.Get("mockDB/salt.txt", username)
	passwd, _ := mockDB.Get("mockDB/users.txt", username)

	// Check password
	password_hash_bytes := sha512.Sum512([]byte(password + salt)[:])
	password_hash := hex.EncodeToString(password_hash_bytes[:])
	if password_hash != passwd {
		log.Printf("Invalid login attempt for user %s", username)
		http.Error(w, "Invalid credentials", http.StatusForbidden)
		return
	}

	// Check if user already has a session cookie assigned
	_, err := mockDB.Get("mockDB/sessions.txt", username)
	if err == nil {
		mockDB.Delete("mockDB/sessions.txt", username)
		mockDB.Delete("mockDB/sessions_expire.txt", username)
	}

	// Create session cookie
	session, _ := rand.Int(rand.Reader, big.NewInt(1_000_000_000_000))
	if mockDB.Append("mockDB/sessions.txt", session.String(), username) != nil {
		log.Printf("Error creating session cookie for user %s", username)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if mockDB.Append("mockDB/sessions_expire.txt", session.String(), fmt.Sprint(time.Now().Add(5*time.Minute).Unix())) != nil {
		log.Printf("Error creating session cookie for user %s", username)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	expiration := time.Now().Add(5 * time.Minute)
	cookie := http.Cookie{ // https://pkg.go.dev/net/http#Cookie
		Name:     "session",
		Value:    session.String(),
		Expires:  expiration,
		MaxAge:   300,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &cookie)

	// Redirect to homepage
	http.Redirect(w, r, "/app", http.StatusFound)
	log.Printf("User %s logged in", username)
}

// Logout function. Delete session cookie
func logout(w http.ResponseWriter, r *http.Request) {
	// Get session cookie
	cookie, err := r.Cookie("session")

	if err != nil {
		if err == http.ErrNoCookie {
			http.Redirect(w, r, "/notLoggedIn.html", http.StatusFound)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Delete session cookie
	cookie.Expires = time.Now().AddDate(0, 0, -1)
	http.SetCookie(w, cookie)

	mockDB.Delete("mockDB/sessions.txt", cookie.Value)
	mockDB.Delete("mockDB/sessions_expire.txt", cookie.Value)

	// Redirect to homepage (confirm logout)
	http.ServeFile(w, r, "app/logout.html")
}

// Serve app function. Check if session cookie is valid and serve the app. If not, redirect to login page
func serveApp(w http.ResponseWriter, r *http.Request) {
	// Get session cookie
	cookie, err := r.Cookie("session")

	if err != nil {
		if err == http.ErrNoCookie {
			http.Redirect(w, r, "/notLoggedIn.html", http.StatusFound)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check session cookie
	_, err = mockDB.Get("mockDB/sessions.txt", cookie.Value)
	if err == nil {
		http.ServeFile(w, r, "app/main.html")
		return
	}

	// Could not validate session cookie, redirect to login page
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Maintain session cookies. Check if session cookie is expired and delete it
func clearExpiredSessions() {
	for range time.Tick(time.Minute * 1) {
		sessions_map, err := mockDB.GetAll("mockDB/sessions_expire.txt")
		if err != nil {
			log.Printf("Error clearing expired sessions: %s", err)
			continue
		}

		for session, expire := range sessions_map {
			var exp_int int64
			fmt.Sscan(expire, &exp_int)
			if time.Now().Unix() > exp_int {
				mockDB.Delete("mockDB/sessions.txt", session)
				mockDB.Delete("mockDB/sessions_expire.txt", session)
			}
		}

		log.Printf("Cleared expired sessions")
	}
}

func main() {
	http.Handle("/", http.FileServer(http.Dir("static"))) // This could be Nginx and act as a reverse proxy for the app or other services
	http.HandleFunc("/login", login)
	http.HandleFunc("/auth", authenticate)
	http.HandleFunc("/app", serveApp)
	http.HandleFunc("/logout", logout)

	go clearExpiredSessions() // Start session cookie maintenance goroutine

	fmt.Println("Listening on port 8080: https://localhost:8080")
	http.ListenAndServeTLS(":8080", "cert/cert.pem", "cert/key.pem", nil)
}