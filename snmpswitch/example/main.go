package main

import (
	"fmt"
	"time"

	"github.com/computerphysicslab/goPackages/goDebug"
	"github.com/computerphysicslab/hsap/libsnmp"
	"github.com/spf13/viper"
)

func nowAsUnixMilli() int64 {
	return time.Now().UnixNano() / 1e6
}

func main() {
	// Config
	viper.SetConfigName("goSwitchSNMP") // name of config file (without extension)
	viper.AddConfigPath(".")            // look for config in the working directory
	err := viper.ReadInConfig()         // Find and read the config file
	if err != nil {                     // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s", err))
	}

	// Loading hardcoded network structure
	var N snmplib.Network
	err = viper.Unmarshal(&N)
	if err != nil {
		panic(fmt.Errorf("Unable to decode into struct, %v", err))
	}
	// goDebug.Print("network", N)
	// fmt.Printf("N: %#v\n\n", N)
	// os.Exit(0)

	// Get master table
	mainSwitchArpTable := snmplib.GetMasterIPmacTable(N)
	goDebug.Print("mainSwitchArpTable", mainSwitchArpTable)

	// Benchmarking concurrency of snmpLib
	t00 := nowAsUnixMilli()

	// Check IP: given an IP loop every switch querying its ARP table looking for an IP matching
	ipToFind := "10.36.11.205"
	IPscan := libsnmp.ScanIP(ipToFind, N)
	goDebug.Print("IPscan", IPscan)

	// Benchmarking concurrency of snmpLib, results
	fmt.Printf("\n\nFull process time elapsed: %.3f s", (float64(nowAsUnixMilli()-t00))/1000.0)
	fmt.Printf("\n\n")

	// Full process time elapsed: 8.927 s, 9.193 s => synchronously
	// Full process time elapsed: 0.518 s =>  w/ gorutines

}