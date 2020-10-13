package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/computerphysicslab/hsap/libsnmp"
	"github.com/computerphysicslab/hsap/libstruct"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func nowAsUnixMilli() int64 {
	return time.Now().UnixNano() / 1e6
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
	var N libsnmp.Network
	err = viper.Unmarshal(&N)
	if err != nil {
		panic(fmt.Errorf("Unable to decode into struct, %v", err))
	}
	// libstruct.Print("network", N)
	// fmt.Printf("N: %#v\n\n", N)
	// os.Exit(0)

	multipleQuery := libsnmp.GetOIDsSubtree("10.41.137.129", "SACYLCom", []string{"1.3.6.1.4.1.9.9.128.1.1.1.1.3", "1.3.6.1.2.1.3.1.1.2.149"})
	libstruct.Print("multipleQuery", multipleQuery)
	os.Exit(0)

	// Get master table
	mainSwitchArpTable := libsnmp.GetMasterIPmacTable(N)
	libstruct.Print("mainSwitchArpTable", mainSwitchArpTable)

	// Benchmarking concurrency of snmpLib
	t00 := nowAsUnixMilli()

	// Check IP: given an IP loop every switch querying its ARP table looking for an IP matching
	ipToFind := "10.36.11.205"
	IPscan := libsnmp.ScanIP(ipToFind, N)
	libstruct.Print("IPscan", IPscan)

	// Benchmarking concurrency of snmpLib, results
	fmt.Printf("\n\nFull process time elapsed: %.3f s", (float64(nowAsUnixMilli()-t00))/1000.0)
	fmt.Printf("\n\n")

	// Full process time elapsed: 8.927 s, 9.193 s => synchronously
	// Full process time elapsed: 0.518 s =>  w/ gorutines

}
