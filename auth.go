package main

import (
	"fmt"
	"net/http"
	"time"
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
	if cookie.Value == "123456789" {
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
	if username != "admin" || password != "admin" {
		http.Error(w, "Invalid credentials", http.StatusForbidden)
		return
	}

	// Create session cookie
	expiration := time.Now().Add(5 * time.Minute)
	cookie := http.Cookie{ // https://pkg.go.dev/net/http#Cookie
		Name:     "session",
		Value:    "123456789",
		Expires:  expiration,
		MaxAge:   300,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &cookie)

	// Redirect to homepage
	http.Redirect(w, r, "/app", http.StatusFound)
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
	if cookie.Value == "123456789" {
		http.ServeFile(w, r, "app/main.html")
		return
	}

	// Could not validate session cookie, redirect to login page
	http.Redirect(w, r, "/login", http.StatusFound)
}

func main() {
	http.Handle("/", http.FileServer(http.Dir("static"))) // This could be Nginx and act as a reverse proxy for the app or other services
	http.HandleFunc("/login", login)
	http.HandleFunc("/auth", authenticate)
	http.HandleFunc("/app", serveApp)
	http.HandleFunc("/logout", logout)

	fmt.Println("Listening on port 8080: https://localhost:8080")
	http.ListenAndServeTLS(":8080", "cert/cert.pem", "cert/key.pem", nil)
}
