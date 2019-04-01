package main

import (
	"encoding/json"
	"net/http"
	"os"
)

type Configuration struct {
	OAuthClientID     string
	OAuthClientSecret string
	OAuthRedirect     string
	Domain            string
	AuthDomain        string
	AuthPort          int
	AuthIP            string
	SecretValue       string
	Backends          []Backend
	EmailWhitelist    []string
	AddressWhitelist  []string
	TrustedAddresses  []string
	RealIPHeader      string
}

var config *Configuration

func init() {
	// Get configuration from conf.json
	file, _ := os.Open("conf.json")
	decoder := json.NewDecoder(file)
	_ = decoder.Decode(&config)
}

func main() {
	go basicBackend()
	auth := NewAuth(config.OAuthClientID, config.OAuthClientSecret, config.OAuthRedirect, []byte(config.SecretValue), config.Domain, config.AuthDomain)
	auth.ParseWhitelist(config.EmailWhitelist)
	proxy := NewProxy(config.Domain, config.AuthDomain, config.AuthPort, config.AuthIP, config.SecretValue, auth, config.RealIPHeader)
	proxy.ParseBackends(config.Backends)
	proxy.ParseTrustedAddresses(config.TrustedAddresses)
	proxy.ParseAddressWhitelist(config.AddressWhitelist)
	proxy.StartProxy()

}

func basicBackend() {
	server1 := http.NewServeMux()
	server1.HandleFunc("/", basicResponse)
	if err := http.ListenAndServe(":82", server1); err != nil {
		panic(err)
	}
}

func basicResponse(res http.ResponseWriter, req *http.Request) {

	res.Write([]byte("Test"))
}
