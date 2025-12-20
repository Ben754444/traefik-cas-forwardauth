package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/html/charset"
)

type ServiceResponse struct {
	User string `xml:"authenticationSuccess>user"`
}

func isWhitelisted(user string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return true
	}
	for _, u := range whitelist {
		if u == user {
			return true
		}
	}
	return false
}

func genToken(user string, hmacSecret []byte) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
		"exp":  jwt.NewNumericDate(time.Now().Add(6 * time.Hour)),
	})
	tokenString, err := token.SignedString(hmacSecret)
	if err != nil {
		return ""
	}
	return tokenString
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))

	casUrl, err := url.ParseRequestURI(os.Getenv("CAS_URL"))
	if err != nil {
		println("Invalid CAS_URL:", err.Error())
		return
	}
	appUrl, err := url.ParseRequestURI(os.Getenv("APP_URL"))
	if err != nil {
		println("Invalid APP_URL:", err.Error())
		return
	}
	// prevents other hosts from pointing to it
	proxyUrl, err := url.ParseRequestURI(os.Getenv("PROXY_URL"))
	if err != nil {
		println("Invalid PROXY_URL:", err.Error())
		return
	}

	hmacSecret := []byte(os.Getenv("JWT_SECRET"))
	if len(hmacSecret) == 0 {
		println("JWT_SECRET is not set")
		return
	}

	whitelist := os.Getenv("WHITELISTED_USERS")
	var whitelistArr []string
	if whitelist != "" {
		whitelistArr = strings.Split(whitelist, ",")
	}

	errorFile := os.Getenv("ERROR_FILE")
	var errorData []byte
	if errorFile != "" {
		_, err := os.Stat(errorFile)
		if os.IsNotExist(err) {
			println("ERROR_FILE does not exist:", errorFile)
			return
		}

		if err != nil {
			println("Failed to read ERROR_FILE:", err.Error())
			return
		}
		errorData, err = os.ReadFile(errorFile)

	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		newUrl := &url.URL{
			Scheme:   proxyUrl.Scheme,
			Opaque:   proxyUrl.Opaque,
			Host:     proxyUrl.Host,
			User:     proxyUrl.User,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			Fragment: r.URL.Fragment,
		}
		// if authenticated
		cookie, err := r.Cookie("session_id")
		if err == nil {
			token, _ := jwt.Parse(cookie.Value, func(token *jwt.Token) (any, error) {
				return hmacSecret, nil
			}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

			if token == nil || !token.Valid {
				http.SetCookie(w, &http.Cookie{
					Name:   "session_id",
					MaxAge: -1,
				})
				http.Redirect(w, r, casUrl.String()+"/login?service="+url.QueryEscape(newUrl.String()), http.StatusFound)
				return
			}

			println("TOKEN VALID")

			user := token.Claims.(jwt.MapClaims)["user"].(string)

			remaining := jwt.NewNumericDate(time.Now()).Unix() - int64(token.Claims.(jwt.MapClaims)["exp"].(float64))

			if remaining < 5*60*60 {
				http.SetCookie(w, &http.Cookie{
					Name:   "session_id",
					Value:  genToken(user, hmacSecret),
					MaxAge: 6 * 60 * 60,
				})
			}

			if !isWhitelisted(user, whitelistArr) {
				slog.Debug("User not whitelisted:", slog.String("user", user))
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}

			proxy := httputil.ReverseProxy{
				Director: func(req *http.Request) {
					req.URL.Scheme = appUrl.Scheme
					req.URL.Host = appUrl.Host
					req.URL.Path = appUrl.Path + r.URL.Path
					req.Host = appUrl.Host
					for k, v := range r.Header {
						req.Header[k] = v
					}
					req.Header.Set("X-User", user)
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					slog.Debug("Proxy error:", slog.String("error", err.Error()))
					// read and send html file
					if errorData != nil {
						w.Header().Set("Content-Type", "text/html")
						w.WriteHeader(http.StatusBadGateway)
						w.Write(errorData)
					} else {
						http.Error(w, "upstream communication error", http.StatusBadGateway)
					}

				},
			}
			proxy.ServeHTTP(w, r)
			return
		}

		if r.URL.Query().Get("ticket") != "" {
			ticket := r.URL.Query().Get("ticket")
			// remove ticket from URL
			query := r.URL.Query()
			query.Del("ticket")
			rawQuery := query.Encode()
			// r.URL doesnt have the fucking scheme (or probably host) guessing cuz of http.handleFunc starting at /.
			// go back to proxy_url maybe but that was beong weird
			newUrl := &url.URL{
				Scheme:   proxyUrl.Scheme,
				Opaque:   proxyUrl.Opaque,
				Host:     proxyUrl.Host,
				User:     proxyUrl.User,
				Path:     r.URL.Path,
				RawQuery: rawQuery,
				Fragment: r.URL.Fragment,
			}
			println(newUrl.String())
			serviceValidation, err := http.Get(casUrl.String() + "/serviceValidate?service=" + url.QueryEscape(newUrl.String()) + "&ticket=" + ticket)
			if err != nil || serviceValidation.StatusCode != http.StatusOK {
				slog.Debug("Failed to validate CAS ticket:", slog.String("error", err.Error()))
				http.Error(w, "CAS communication error", http.StatusInternalServerError)
				return
			}

			defer serviceValidation.Body.Close()

			body, err := io.ReadAll(serviceValidation.Body)
			if err != nil {
				slog.Debug("Failed to read CAS response:", slog.String("error", err.Error()))
				http.Error(w, "CAS communication error", http.StatusInternalServerError)
				return
			}

			// parse xml
			var serviceResponse ServiceResponse
			decoder := xml.NewDecoder(bytes.NewReader(body))
			decoder.CharsetReader = charset.NewReaderLabel
			if err := decoder.Decode(&serviceResponse); err != nil {
				slog.Debug("Failed to parse CAS response:", slog.String("error", err.Error()))
				http.Error(w, "CAS communication error", http.StatusInternalServerError)
				return
			}

			if serviceResponse.User == "" {
				slog.Debug("CAS authentication failed: no user in response")
				slog.Debug("CAS response:", slog.String("response", string(body)))
				//http.Error(w, "CAS authentication failed", http.StatusUnauthorized)
				http.Redirect(w, r, casUrl.String()+"/login?service="+url.QueryEscape(newUrl.String()), http.StatusFound)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:   "session_id",
				Value:  genToken(serviceResponse.User, hmacSecret),
				MaxAge: 6 * 60 * 60,
			})

			// remove ticket query
			originalUrl := r.URL
			q := originalUrl.Query()
			q.Del("ticket")
			originalUrl.RawQuery = q.Encode()
			http.Redirect(w, r, proxyUrl.String()+originalUrl.String(), http.StatusFound)

			return
		}

		http.Redirect(w, r, casUrl.String()+"/login?service="+url.QueryEscape(newUrl.String()), http.StatusFound)

	})

	println("CAS URL:", casUrl.String())
	println("App URL:", appUrl.String())
	println("Proxy URL:", proxyUrl.String())

	println("Starting proxy server on :8080")
	err = http.ListenAndServe(":8080", nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
