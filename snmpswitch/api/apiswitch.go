//
// Lanza API en goLang que consulta por SNMP la tabla ARP principal de IPs
// y realiza un full scan de busqueda de una IP entre los switches de red
//
// apiswitch.go
//
// Boot the server:
// ----------------
// $ go run apiswitch.go
//
// Boot the server on background:
// ------------------------------
// $ nohup go run apiswitch.go > api.log 2>&1 &
//
// Client requests:
// ----------------
//
// To check the API:
// $ curl -iX GET http://localhost:3333/test
//
// To check the API endpoints:
// $ curl -iX GET http://localhost:3333/swagger
//
// To get the main ARP table:
// $ curl -iX GET http://localhost:3333/mainSwitchArpTable
//
// To get the switch matching table for a given IP address:
// $ curl -iX GET http://localhost:3333/IPscan/10.36.11.205
//

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/computerphysicslab/hsap/libsnmp"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// @title goSwitchSNMP API
// @version 1.0
// @description API en goLang que consulta por SNMP los switches de red

// @contact.name Departamento de Informática del Hospital Santiago Apóstol (Miranda de Ebro) de hsap
// @contact.url http://www.hsap.sacyl.es/
// @contact.email informatica.hsap@saludcastillayleon.es

// @license.name Public domain
// @license.url https://creativecommons.org/publicdomain/zero/1.0/

// @host localhost:3333
// @BasePath /

/***********************/
/* Global variables ****/
/***********************/

var myNetwork libsnmp.Network

/***********************/
/* JSON API responders */
/***********************/

// respondWithError return for handlers w/ JSON error message
func respondWithError(w http.ResponseWriter, code int, msg string, _type string) {
	respondWithJSON(w, code, map[string]map[string]string{"error": {"message": msg, "type": _type}})
}

// respondWithJSON write json response format
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		os.Stderr.WriteString("Oops: " + err.Error() + "\n")
		panic(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

/****************/
/* API handlers */
/****************/

// / godoc
// @Summary Shows API description
// @Produce plain
// @Success 200 {string} string	"ok"
// @Router / [get]
func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("This is root endpoint. Check out /test endpoint for further info"))
}

// test godoc
// @Summary Performs a minimal test showing API ip address, server time
// @Produce json
// @Success 200 {string} string	"ok"
// @Router /test [get]
func testHandler(w http.ResponseWriter, r *http.Request) {
	// Getting API local IP address
	var ips bytes.Buffer
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		os.Stderr.WriteString("Oops: " + err.Error() + "\n")
		respondWithError(w, 500, err.Error(), "NetException")
		panic(err)
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips.Write([]byte(ipnet.IP.String()))
				ips.Write([]byte(", "))
			}
		}
	}

	serverIPValue := strings.TrimRight(ips.String(), ", ")

	// Getting API current time
	currentTime := time.Now()
	serverTimeValue := currentTime.Format("2006-01-02 15:04:05")

	respondWithJSON(w, 200, map[string]string{"serverIP": serverIPValue, "serverTime": serverTimeValue})
}

// swagger godoc
// @Summary Displays JSON w/ API doc built by swaggo
// @Produce json
// @Success 200 {string} string	"ok"
// @Router /swagger [get]
func swaggerHandler(w http.ResponseWriter, r *http.Request) {
	dat, err := ioutil.ReadFile("docs/swagger.json")
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("%v", err), "IOException")
		panic(err)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(dat)
	}
}

// mainSwitchArpTable godoc
// @Summary Displays JSON w/ main switch ARP table (IP => MAC)
// @Produce json
// @Success 200 {string} string	"ok"
// @Router /mainSwitchArpTable [get]
func snmpMainSwitchArpTableJSON(w http.ResponseWriter, r *http.Request) {
	mainSwitchArpTable := libsnmp.GetMasterIPmacTable(myNetwork)

	respondWithJSON(w, 200, mainSwitchArpTable)
}

// IPscan godoc
// @Summary Displays JSON w/ matching ports on network switches for a given IP address
// @Produce json
// @Param ipToFind path string true "IP address to scan"
// @Success 200 {string} string	"ok"
// @Router /IPscan [get]
func snmpIPscanJSON(w http.ResponseWriter, r *http.Request) {
	ipToFind := chi.URLParam(r, "ipToFind")
	IPscan := libsnmp.ScanIP(ipToFind, myNetwork)

	respondWithJSON(w, 200, IPscan)
}

func main() {
	// Command line parameters/flags
	flag.String("viperConfigName", "myNetwork", "network config filename")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viperConfigName := viper.GetString("viperConfigName")
	fmt.Printf("viperConfigName: %+v\n", viperConfigName)

	// Loading config YAML
	viper.SetConfigName(viperConfigName) // name of config file (without extension)
	viper.AddConfigPath(".")             // look for config in the working directory
	err := viper.ReadInConfig()          // Find and read the config file
	if err != nil {                      // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s", err))
	}

	// Loading hardcoded network structure
	err = viper.Unmarshal(&myNetwork)
	if err != nil {
		panic(fmt.Errorf("Unable to decode into struct, %v", err))
	}
	// goDebug.Print("network", N)
	// fmt.Printf("N: %#v\n\n", N)
	// os.Exit(0)

	// go-chi router
	r := chi.NewRouter() // new Mux object

	// go-chi middlewares
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(viper.GetDuration("timeout") * time.Second))
	r.Use(middleware.RedirectSlashes) // redirects .../test/ into .../test

	// root endpoint route
	r.Get("/root", rootHandler) // GET /root

	// test endpoint route
	r.Get("/test", testHandler) // GET /test

	// swagger endpoint route
	r.Get("/swagger", swaggerHandler) // GET /swagger

	// mainSwitch endpoint route
	r.Get("/mainSwitchArpTable", snmpMainSwitchArpTableJSON) // GET /mainSwitchArpTable

	// IPscan endpoint route
	r.Route("/IPscan", func(r chi.Router) {
		r.Get("/{ipToFind:[0-9]+.[0-9]+.[0-9]+.[0-9]+}", snmpIPscanJSON) // GET /IPscan/<IP>
	})

	fmt.Printf("Browse http://localhost:3333/test\n\n")

	log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), r)) // Launch server
}
