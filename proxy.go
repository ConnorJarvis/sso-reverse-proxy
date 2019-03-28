package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Proxy struct {
	Domain                string
	AuthDomain            string
	AuthPort              int
	AuthIP                string
	Backends              map[string]*ParsedBackend
	AddressWhitelist      []string
	BackendsMutex         *sync.RWMutex
	Auth                  Auth
	TrustedAddresses      map[string]bool
	TrustedAddressesMutex *sync.RWMutex
	RealIPHeader          string
}

type ParsedBackend struct {
	Domain              string
	Backend             string
	EmailWhitelist      map[string]bool
	AddressWhitelist    []string
	EmailWhitelistMutex *sync.RWMutex
}

type Backend struct {
	Domain           string
	Backend          string
	EmailWhitelist   []string
	AddressWhitelist []string
}

func NewProxy(Domain, AuthDomain string, AuthPort int, AuthIP, SecretValue string, Auth Auth, RealIPHeader string) Proxy {
	return Proxy{Domain: Domain, AuthDomain: AuthDomain, AuthPort: AuthPort, AuthIP: AuthIP, Auth: Auth, Backends: make(map[string]*ParsedBackend), BackendsMutex: new(sync.RWMutex), TrustedAddressesMutex: new(sync.RWMutex), RealIPHeader: RealIPHeader}
}

func (p *Proxy) ParseAddressWhitelist(AddressWhitelist []string) error {
	p.AddressWhitelist = AddressWhitelist
	return nil
}

func (p *Proxy) ParseTrustedAddresses(TrustedAddresses []string) error {
	p.TrustedAddressesMutex.Lock()
	TrustedAddressesMap := make(map[string]bool)
	for i := 0; i < len(TrustedAddresses); i++ {
		TrustedAddressesMap[TrustedAddresses[i]] = true
	}
	p.TrustedAddresses = TrustedAddressesMap
	p.TrustedAddressesMutex.Unlock()
	return nil
}

func (p *Proxy) ParseBackends(Backends []Backend) error {
	p.BackendsMutex.Lock()
	for i := 0; i < len(Backends); i++ {
		whitelist := make(map[string]bool)
		for a := 0; a < len(Backends[i].EmailWhitelist); a++ {
			whitelist[Backends[i].EmailWhitelist[a]] = true

		}
		parsedBackend := &ParsedBackend{Domain: Backends[i].Domain, Backend: Backends[i].Backend, EmailWhitelist: whitelist, AddressWhitelist: Backends[i].AddressWhitelist, EmailWhitelistMutex: new(sync.RWMutex)}
		p.Backends[Backends[i].Domain] = parsedBackend
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
			http.SetCookie(res, &http.Cookie{"return_url", req.URL.Query().Get("return_url"), "/", p.AuthDomain, time.Now().Add(time.Minute * 5), time.Now().Add(time.Minute * 5).Format(time.UnixDate), 300, false, false, 2, "return_url=" + req.URL.Query().Get("return_url"), []string{"return_url=" + req.URL.Query().Get("return_url")}})
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
			http.SetCookie(res, &http.Cookie{"state", state.String(), "/", p.AuthDomain, time.Now().Add(time.Minute * 5), time.Now().Add(time.Minute * 5).Format(time.UnixDate), 300, false, false, 2, "state=" + state.String(), []string{"state=" + state.String()}})

			url := p.Auth.GenerateURL(state.String())
			http.Redirect(res, req, url, 307)
		}

	} else if backend != nil {
		err := p.Auth.ValidateJWT(res, req, *backend)
		if err != nil {
			http.Redirect(res, req, "http://"+p.AuthDomain+"/?return_url="+url.QueryEscape(requestedURL), 307)
			return
		}

		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			http.Redirect(res, req, "http://"+p.AuthDomain+"/?return_url="+url.QueryEscape(requestedURL), 307)
			return
		}

		p.TrustedAddressesMutex.RLock()
		defer p.TrustedAddressesMutex.RUnlock()
		if p.TrustedAddresses[host] {
			host = req.Header.Get(p.RealIPHeader)
		}

		if !p.CheckIP(host, backend.Domain) {
			fmt.Println("Bad IP")
			http.Redirect(res, req, "http://"+p.AuthDomain+"/?return_url="+url.QueryEscape(requestedURL), 307)
			return
		}
		p.serveReverseProxy(backend.Backend+req.URL.RequestURI(), res, req)

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

func (p *Proxy) CheckIP(ip, host string) bool {
	p.BackendsMutex.RLock()
	backend := p.Backends[host]
	p.BackendsMutex.RUnlock()
	if len(backend.AddressWhitelist) == 0 {
		fmt.Println("No backend specific range")
		for i := 0; i < len(p.AddressWhitelist); i++ {
			_, ipRange, err := net.ParseCIDR(p.AddressWhitelist[i])
			if err != nil {
				fmt.Println(err)
				return false
			}
			if ipRange.Contains(net.ParseIP(ip)) {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(backend.AddressWhitelist); i++ {
		_, ipRange, err := net.ParseCIDR(backend.AddressWhitelist[i])
		if err != nil {
			fmt.Println(err)
			return false
		}
		if ipRange.Contains(net.ParseIP(ip)) {
			return true
		}
	}

	return false
}
