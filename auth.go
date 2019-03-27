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
	OAuthClientID     string
	OAuthClientSecret string
	OAuthRedirect     string
	SecretValue       []byte
	Domain            string
	Whitelist         map[string]bool
	WhitelistMutex    *sync.RWMutex
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

func NewAuth(OAuthClientID, OAuthClientSecret, OAuthRedirect string, SecretValue []byte, Domain string) Auth {
	return Auth{OAuthClientID: OAuthClientID, OAuthClientSecret: OAuthClientSecret, OAuthRedirect: OAuthRedirect, SecretValue: SecretValue, Domain: Domain, Whitelist: make(map[string]bool), WhitelistMutex: new(sync.RWMutex)}
}

func (a *Auth) ParseWhitelist(Whitelist []string) error {
	a.WhitelistMutex.Lock()
	for i := 0; i < len(Whitelist); i++ {
		a.Whitelist[Whitelist[i]] = true
	}
	a.WhitelistMutex.Unlock()
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
	stateCookie, err := req.Cookie("state")
	if err != nil {
		return err
	}
	if stateCookie.Value != req.URL.Query().Get("state") {
		res.Write([]byte("Mismatching state"))
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

func (a *Auth) SetupJWT(res http.ResponseWriter, req *http.Request, email string) error {
	a.WhitelistMutex.RLock()
	if a.Whitelist[email] != true {
		a.WhitelistMutex.RUnlock()
		return errors.New("Email is not whitelisted")
	}
	a.WhitelistMutex.RUnlock()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"nbf":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(a.SecretValue)
	if err != nil {
		fmt.Println(err)
	}
	http.SetCookie(res, &http.Cookie{"SSO-Token", tokenString, "/", a.Domain, time.Now().Add(time.Hour), time.Now().Add(time.Hour).Format(time.UnixDate), 3600, false, false, 0, "SSO-Token=" + tokenString, []string{"SSO-Token=" + tokenString}})
	return nil
}

func (a *Auth) ValidateJWT(res http.ResponseWriter, req *http.Request) error {
	SSOToken, err := req.Cookie("SSO-Token")
	if err != nil {
		return errors.New("Cookier Error")
	}
	token, err := jwt.Parse(SSOToken.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return a.SecretValue, nil
	})
	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		return nil
	} else {
		return errors.New("Token Error")
	}
}
