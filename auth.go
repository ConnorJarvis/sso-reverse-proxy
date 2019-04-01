package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Auth struct {
	OAuthClientID       string
	OAuthClientSecret   string
	OAuthRedirect       string
	SecretValue         []byte
	Domain              string
	AuthDomain          string
	EmailWhitelist      map[string]bool
	EmailWhitelistMutex *sync.RWMutex
}

type UserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
}

func NewAuth(OAuthClientID, OAuthClientSecret, OAuthRedirect string, SecretValue []byte, Domain, AuthDomain string) Auth {
	return Auth{OAuthClientID: OAuthClientID, OAuthClientSecret: OAuthClientSecret, OAuthRedirect: OAuthRedirect, SecretValue: SecretValue, Domain: Domain, AuthDomain: AuthDomain, EmailWhitelist: make(map[string]bool), EmailWhitelistMutex: new(sync.RWMutex)}
}

func (a *Auth) ParseWhitelist(EmailWhitelist []string) error {
	a.EmailWhitelistMutex.Lock()
	for i := 0; i < len(EmailWhitelist); i++ {
		a.EmailWhitelist[EmailWhitelist[i]] = true
	}
	a.EmailWhitelistMutex.Unlock()
	return nil
}

func (a *Auth) GenerateURL(state string) string {
	conf := &oauth2.Config{
		ClientID:     a.OAuthClientID,
		ClientSecret: a.OAuthClientSecret,
		RedirectURL:  a.OAuthRedirect,
		Scopes: []string{
			"profile",
			"email",
		},
		Endpoint: google.Endpoint,
	}
	url := conf.AuthCodeURL(state)
	return url
}

func (a *Auth) ProcessCallback(res http.ResponseWriter, req *http.Request) error {
	conf := &oauth2.Config{
		ClientID:     a.OAuthClientID,
		ClientSecret: a.OAuthClientSecret,
		RedirectURL:  a.OAuthRedirect,
		Scopes: []string{
			"email",
		},
		Endpoint: google.Endpoint,
	}
	state, err := a.ValidateState(res, req)
	if err != nil {
		return err
	}
	if state != req.URL.Query().Get("state") {
		return errors.New("Mismatching state")
	}
	tok, err := conf.Exchange(oauth2.NoContext, req.URL.Query().Get("code"))
	if err != nil {
		return err
	}
	client := conf.Client(oauth2.NoContext, tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var result UserInfo
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	err = a.SetupJWT(res, req, result.Email)
	if err != nil {
		return err
	}
	return nil
}

func (a *Auth) CreateStateJWT(res http.ResponseWriter, req *http.Request, state string) error {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"state": state,
		"nbf":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(a.SecretValue)
	if err != nil {
		return err
	}
	cookie := &http.Cookie{Name: "State", Value: tokenString, Path: "/", Domain: a.AuthDomain, Expires: time.Now().Add(time.Hour), Secure: true, SameSite: 2}
	http.SetCookie(res, cookie)
	return nil
}

func (a *Auth) SetupJWT(res http.ResponseWriter, req *http.Request, email string) error {
	a.EmailWhitelistMutex.RLock()
	if a.EmailWhitelist[email] != true {
		a.EmailWhitelistMutex.RUnlock()
		return errors.New("Email is not whitelisted")
	}
	a.EmailWhitelistMutex.RUnlock()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"nbf":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(a.SecretValue)
	if err != nil {
		fmt.Println(err)
	}
	cookie := &http.Cookie{Name: "SSO-Token", Value: tokenString, Path: "/", Domain: a.Domain, Expires: time.Now().Add(time.Hour), Secure: true, SameSite: 2}
	http.SetCookie(res, cookie)
	return nil
}

func (a *Auth) ValidateState(res http.ResponseWriter, req *http.Request) (string, error) {
	SSOToken, err := req.Cookie("State")
	if err != nil {
		return "", errors.New("Cookie Error")
	}
	token, err := jwt.Parse(SSOToken.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return a.SecretValue, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		state := claims["state"].(string)

		return state, nil
	} else {
		return "", errors.New("Token Error")
	}
}

func (a *Auth) ValidateJWT(res http.ResponseWriter, req *http.Request, backend ParsedBackend) error {
	SSOToken, err := req.Cookie("SSO-Token")
	if err != nil {
		return errors.New("Cookie Error")
	}
	token, err := jwt.Parse(SSOToken.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return a.SecretValue, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		email := claims["email"].(string)
		backend.EmailWhitelistMutex.RLock()
		if len(backend.EmailWhitelist) == 0 {
			a.EmailWhitelistMutex.RLock()
			if a.EmailWhitelist[email] != true {
				a.EmailWhitelistMutex.RUnlock()
				backend.EmailWhitelistMutex.RUnlock()
				return errors.New("Email is not whitelisted")
			}
		} else {
			if backend.EmailWhitelist[email] != true {
				backend.EmailWhitelistMutex.RUnlock()
				return errors.New("Email is not whitelisted")
			}
		}
		expiry := claims["exp"].(float64)
		fmt.Println(int64(expiry) - time.Now().Unix())
		if int64(expiry)-time.Now().Unix() < 300 {
			a.SetupJWT(res, req, email)
		}
		return nil
	} else {
		return errors.New("Token Error")
	}
}
