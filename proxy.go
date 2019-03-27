package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Proxy struct {
	Domain        string
	AuthDomain    string
	AuthPort      int
	AuthIP        string
	Backends      map[string]*string
	BackendsMutex *sync.RWMutex
	Auth          Auth
}

type Backend struct {
	Domain  string
	Backend string
}

func NewProxy(Domain, AuthDomain string, AuthPort int, AuthIP, SecretValue string, Auth Auth) Proxy {
	return Proxy{Domain: Domain, AuthDomain: AuthDomain, AuthPort: AuthPort, AuthIP: AuthIP, Auth: Auth, Backends: make(map[string]*string), BackendsMutex: new(sync.RWMutex)}
}

func (p *Proxy) ParseBackends(Backends []Backend) error {
	p.BackendsMutex.Lock()
	for i := 0; i < len(Backends); i++ {
		p.Backends[Backends[i].Domain] = &Backends[i].Backend
	}
	p.BackendsMutex.Unlock()
	return nil
}

func (p *Proxy) StartProxy() {
	http.HandleFunc("/", p.handleRequest)

	if err := http.ListenAndServe(p.AuthIP+":"+strconv.Itoa(p.AuthPort), nil); err != nil {
		panic(err)
	}
}

func (p *Proxy) handleRequest(res http.ResponseWriter, req *http.Request) {
	requestedURL := req.Host + req.URL.RequestURI()
	p.BackendsMutex.RLock()
	backend := p.Backends[req.Host]
	p.BackendsMutex.RUnlock()

	if req.Host == config.AuthDomain && req.URL.RequestURI() != "/favicon.ico" {
		if req.URL.Query().Get("return_url") != "" {
			http.SetCookie(res, &http.Cookie{"return_url", req.URL.Query().Get("return_url"), "/", p.Domain, time.Now().Add(time.Minute * 5), time.Now().Add(time.Minute * 5).Format(time.UnixDate), 300, false, false, 0, "return_url=" + req.URL.Query().Get("return_url"), []string{"return_url=" + req.URL.Query().Get("return_url")}})
		}
		if req.URL.Path == "/callback" {
			err := p.Auth.ProcessCallback(res, req)
			if err != nil {
				fmt.Println(err)
			}
			returnURL, err := req.Cookie("return_url")
			if err == nil {
				returnURLString, err := url.QueryUnescape(returnURL.Value)
				if err != nil {
					fmt.Println(err)
				}
				http.Redirect(res, req, "http://"+returnURLString, 307)
				return
			}
		} else {
			state, err := uuid.NewRandom()
			if err != nil {
				fmt.Println(err)
			}
			http.SetCookie(res, &http.Cookie{"state", state.String(), "/", p.Domain, time.Now().Add(time.Minute * 5), time.Now().Add(time.Minute * 5).Format(time.UnixDate), 300, false, false, 0, "state=" + state.String(), []string{"state=" + state.String()}})

			url := p.Auth.GenerateURL(state.String())
			http.Redirect(res, req, url, 307)
		}

	} else if backend != nil {
		err := p.Auth.ValidateJWT(res, req)
		if err != nil {
			http.Redirect(res, req, "http://"+p.AuthDomain+"/?return_url="+url.QueryEscape(requestedURL), 307)
			return
		}
		p.serveReverseProxy(*backend+req.URL.RequestURI(), res, req)

	}

}

func (p *Proxy) serveReverseProxy(target string, res http.ResponseWriter, req *http.Request) {

	url, _ := url.Parse(target)

	proxy := httputil.NewSingleHostReverseProxy(url)

	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	req.Host = url.Host

	proxy.ServeHTTP(res, req)
}
