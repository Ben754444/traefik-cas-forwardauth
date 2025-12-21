package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/html/charset"
)

type ServiceResponse struct {
	User string `xml:"authenticationSuccess>user"`
}

func isInLdapGroups(user string, ldapGroups []string, conn **ldap.Conn) bool {
	if len(ldapGroups) == 0 {
		return true
	}

	slog.Debug("Checking LDAP groups for user:", slog.String("user", user), slog.String("groups", strings.Join(ldapGroups, ", ")))

	searchRequest := ldap.NewSearchRequest("ou=groups,o=bath.ac.uk", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf("(&(objectClass=groupOfNames)(member=uid=%s,ou=people,o=bath.ac.uk))", user), []string{"cn"}, nil)

	sr, err := (*conn).Search(searchRequest)
	if err != nil {
		if err.(*ldap.Error).ResultCode == ldap.ErrorNetwork {
			slog.Debug("LDAP connection lost, reconnecting...")
			var err error
			*conn, err = ldap.DialURL(os.Getenv("LDAP_URL"))
			if err != nil {
				slog.Debug("Failed to reconnect to LDAP server:", slog.String("error", err.Error()))
				return false
			}
			return isInLdapGroups(user, ldapGroups, conn)
		}
		slog.Debug("LDAP search error:", slog.String("error", err.Error()))
		return false

	}

	for _, entry := range sr.Entries {
		groupName := entry.GetAttributeValue("cn")
		for _, g := range ldapGroups {
			if g == groupName {
				return true
			}
		}
	}
	return false

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

func genToken(user string, host string, hmacSecret []byte) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
		"host": host,
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

	hmacSecret := []byte(os.Getenv("JWT_SECRET"))
	if len(hmacSecret) == 0 {
		println("JWT_SECRET is not set")
		return
	}

	ldapUrl := os.Getenv("LDAP_URL")

	var conn *ldap.Conn
	if len(ldapUrl) > 0 {
		conn, err = ldap.DialURL(ldapUrl)
		if err != nil {
			println("Failed to connect to LDAP server:", err.Error())
			return
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var whitelistArr []string
		if len(r.URL.Query().Get("whitelist")) != 0 {
			whitelistArr = strings.Split(r.URL.Query().Get("whitelist"), ",")
		}

		var ldapGroups []string
		if len(r.URL.Query().Get("ldapgroups")) != 0 {
			ldapGroups = strings.Split(r.URL.Query().Get("ldapgroups"), ",")
		}

		originalUrl, err := url.ParseRequestURI(r.Header.Get("X-Forwarded-Uri"))

		if err == nil {
			r.URL = originalUrl
		} else {
			println("Failed to parse X-Forwarded-Url:", err.Error())
		}
		println(r.Header.Get("X-Forwarded-Proto"))
		newUrl := &url.URL{
			Scheme:   r.Header.Get("X-Forwarded-Proto"),
			Host:     r.Header.Get("X-Forwarded-Host"),
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

			if token == nil || !token.Valid || token.Claims.(jwt.MapClaims)["host"].(string) != newUrl.Host {
				http.SetCookie(w, &http.Cookie{
					Name:   "session_id",
					MaxAge: -1,
				})
				http.Redirect(w, r, casUrl.String()+"/login?service="+url.QueryEscape(newUrl.String()), http.StatusFound)
				return
			}

			println("TOKEN VALID")

			user := token.Claims.(jwt.MapClaims)["user"].(string)

			remaining := int64(token.Claims.(jwt.MapClaims)["exp"].(float64)) - jwt.NewNumericDate(time.Now()).Unix()

			// TODO infinite session length
			if remaining < 5*60*60 {
				if !isWhitelisted(user, whitelistArr) {
					slog.Debug("User not whitelisted:", slog.String("user", user))
					http.SetCookie(w, &http.Cookie{
						Name:   "session_id",
						Value:  "",
						MaxAge: -1,
					})
					http.Error(w, "access denied", http.StatusForbidden)
					return
				}

				if len(ldapUrl) > 0 {
					if !isInLdapGroups(user, ldapGroups, &conn) {
						slog.Debug("User not in LDAP groups:", slog.String("user", user))
						// could overload ldap if a valid token cannot be refreshed
						http.SetCookie(w, &http.Cookie{
							Name:   "session_id",
							Value:  "",
							MaxAge: -1,
						})
						http.Error(w, "access denied (ldap)", http.StatusForbidden)
						return
					}
				}

				http.SetCookie(w, &http.Cookie{
					Name:   "session_id",
					Value:  genToken(user, newUrl.Host, hmacSecret),
					MaxAge: 6 * 60 * 60,
				})

				http.Redirect(w, r, newUrl.String(), http.StatusFound)
			}

			w.WriteHeader(http.StatusOK)
			w.Header().Set("X-User", user)
			return

		}

		if r.URL.Query().Get("ticket") != "" {
			ticket := r.URL.Query().Get("ticket")
			// remove ticket from URL
			query := r.URL.Query()
			query.Del("ticket")
			rawQuery := query.Encode()
			newUrl := &url.URL{
				Scheme:   r.Header.Get("X-Forwarded-Proto"),
				Host:     r.Header.Get("X-Forwarded-Host"),
				Path:     r.URL.Path,
				RawQuery: rawQuery,
				Fragment: r.URL.Fragment,
			}
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

			if !isWhitelisted(serviceResponse.User, whitelistArr) {
				slog.Debug("User not whitelisted:", slog.String("user", serviceResponse.User))
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}

			if len(ldapUrl) > 0 {
				if !isInLdapGroups(serviceResponse.User, ldapGroups, &conn) {
					slog.Debug("User not in LDAP groups:", slog.String("user", serviceResponse.User))
					http.Error(w, "access denied (ldap)", http.StatusForbidden)
					return
				}
			}

			http.SetCookie(w, &http.Cookie{
				Name:   "session_id",
				Value:  genToken(serviceResponse.User, newUrl.Host, hmacSecret),
				MaxAge: 6 * 60 * 60,
			})

			// remove ticket query
			http.Redirect(w, r, newUrl.String(), http.StatusFound)
			return
		}
		http.Redirect(w, r, casUrl.String()+"/login?service="+url.QueryEscape(newUrl.String()), http.StatusFound)

	})

	println("CAS URL:", casUrl.String())

	println("Starting proxy server on port", port)
	err = http.ListenAndServe(":"+port, nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
