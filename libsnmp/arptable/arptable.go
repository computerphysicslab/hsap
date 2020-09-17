package libsnmp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// ARPtableItem is an entry of an ARP table, be it a MAC or a Port
type ARPtableItem struct {
	VLAN              string
	MACaddress        string
	MACaddressNumeric string
	Port              int
}

// ARPtable is a mapping of IP => {VLAN, MAC, Port} addresses
type ARPtable map[string]ARPtableItem

// This OID queries IP/Port relations to every device connected on a switch
var oidARPtablePort = "1.3.6.1.2.1.17.4.3.1.2"

// RegEx pattern to extract MAC address (numeric format) from OID name
var regexpGetMacNumFromOIDport = regexp.MustCompile(`^` + oidARPtablePort + `\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$`)

// GetARPtablePort render ARP table (just populating port entry: MAC => Port) of a given switch, by quering the OID using SNMP
func GetARPtablePort(switchIP string, community string) (arpTable ARPtable) {
	arpTable = make(ARPtable) // Initialize inner returning map

	arpTableRAW := GetOIDsubtree(switchIP, community, oidARPtablePort)
	// goDebug.Print("arpTableRAW (port)", arpTableRAW)

	for _, row := range arpTableRAW {
		// fmt.Printf("ROW: %s\n", row)

		var oidResult AnOID
		err := json.Unmarshal([]byte(row), &oidResult)
		if err != nil {
			fmt.Println("JSON unmarshal error: ", err)
		}
		// goDebug.Print("oidResult", oidResult)
		MACaddressNum := regexpGetMacNumFromOIDport.ReplaceAllString(oidResult.Oid, `$1`)
		// Port := oidResult.Variable.Value

		var PortInt int
		fmt.Sscanf(oidResult.Variable.Value, "%d", &PortInt)

		// fmt.Printf("VLAN: %s\n", VLAN)
		// fmt.Printf("MACaddressNum: %s\n", MACaddressNum)
		// fmt.Printf("Port: %s\n", Port)
		// fmt.Printf("PortInt: %d\n", PortInt)
		// fmt.Printf("\n")

		arpTable[MACaddressNum] = ARPtableItem{
			Port: PortInt,
		}
	}

	return
}

// This OID queries IP/MAC relations to every device connected on a switch
var oidARPtable = "1.3.6.1.2.1.3.1.1.2"

// RegEx pattern to extract IP from OID name
var regexpGetIPfromOID = regexp.MustCompile(`^` + oidARPtable + `\.([0-9]+\.[0-9]+)\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$`)

// GetARPtable render ARP table (IP => MAC) of a given switch, by quering the OID using SNMP
func GetARPtable(switchIP string, community string) (arpTable ARPtable) {
	arpTable = make(ARPtable) // Initialize inner returning map

	// get ports on a ARP table indexed by MAC numeric address
	// arpTablePort := GetARPtablePort(switchIP, community)
	// goDebug.Print("arpTablePort", arpTablePort)

	arpTableRAW := GetOIDsubtree(switchIP, community, oidARPtable)
	for _, row := range arpTableRAW {
		// fmt.Printf("ROW: %s\n", row)

		var oidResult AnOID
		err := json.Unmarshal([]byte(row), &oidResult)
		if err != nil {
			fmt.Println("JSON unmarshal error: ", err)
		}
		// goDebug.Print("oidResult", oidResult)
		VLAN := regexpGetIPfromOID.ReplaceAllString(oidResult.Oid, `$1`)
		IPaddress := regexpGetIPfromOID.ReplaceAllString(oidResult.Oid, `$2`)
		MACaddress := oidResult.Variable.Value
		MACaddressSplitted := strings.Split(MACaddress, ":")
		MACaddressNumeric := ""
		for i, MAChex := range MACaddressSplitted {
			intValue, err := strconv.ParseUint(MAChex, 16, 64)
			if err != nil {
				fmt.Println("Hex to Int conversion error: ", err)
			}
			// fmt.Printf("MAChex: %s; intValue: %d\n", MAChex, intValue)
			MACaddressNumeric = MACaddressNumeric + fmt.Sprintf("%d", intValue)
			if i < 5 {
				MACaddressNumeric = MACaddressNumeric + "."
			}
		}

		// fmt.Printf("MACaddressNumeric: %s\n", MACaddressNumeric)
		// os.Exit(0)

		// fmt.Printf("VLAN: %s\n", VLAN)
		// fmt.Printf("IPaddress: %s\n", IPaddress)
		// fmt.Printf("MACaddress: %s\n", MACaddress)
		// fmt.Printf("MACaddressNumeric: %s\n", MACaddressNumeric)
		// fmt.Printf("\n")

		arpTable[IPaddress] = ARPtableItem{
			VLAN:              VLAN,
			MACaddress:        MACaddress,
			MACaddressNumeric: MACaddressNumeric,
			// Port:              arpTablePort[MACaddressNumeric].Port,
		}
	}

	return
}

// Hardcoded switches table schema defines the minimal needed ad hoc network information
// Besides, it is useful to unmarshal hardcoded viper config values into goLang structs

// Node is the node/switch info
type Node struct {
	IP          string `mapstructure:"IP"`
	Community   string `mapstructure:"Community"`
	Description string `mapstructure:"Description"`
	Uplinks     []int  `mapstructure:"Uplinks"`
}

// Network is the full set of nodes/switches
type Network struct {
	// Nodes map[string]Node `mapstructure:"Nodes"`
	Nodes        []Node `mapstructure:"Nodes"`
	MainSwitchIP string `mapstructure:"MainSwitchIP"`
}

// SwitchInfo is the populated record of a switch after scanning
type SwitchInfo struct {
	Description  string
	MatchingPort int
	UplinkPort   bool
}

// SwitchScan is the resulting list of switches after scanning
type SwitchScan map[string]SwitchInfo

// GetMasterIPmacTable queries the master switch to get the master IP=>MAC table
func GetMasterIPmacTable(N Network) ARPtable {
	// Find out main switch community from network config
	mainSwitchCommunity := ""
	for _, node := range N.Nodes {
		if node.IP == N.MainSwitchIP {
			mainSwitchCommunity = node.Community
		}
	}

	// Getting the master IP => MAC table
	mainSwitchArpTable := GetARPtable(N.MainSwitchIP, mainSwitchCommunity)

	return mainSwitchArpTable
}

/*****************************/
/* Concurrent functions ******/
/*****************************/

var wg sync.WaitGroup // https://gobyexample.com/waitgroups
var toggleConcurrency bool = true

// single switch scan as gorutine
func scanIPonSwitch(macNumToFind string, switchIP string, switchCommunity string, switchDescription string, switchUplinks []int, IPscan SwitchScan) {
	// get ARP table of ports from a given switch
	arpTablePort := GetARPtablePort(switchIP, switchCommunity)
	// goDebug.Print("arpTablePort", arpTablePort)

	var isUplink bool

	// loop ARP table entries looking for the full scan MAC matching
	// if port found matches any uplink, it means that the switch does not have a direct connection to the device, so ignore it
	for aMACnum, arpValues := range arpTablePort {
		if aMACnum == macNumToFind {
			// Loop switch uplinks to compare w/ port found
			for _, uplink := range switchUplinks {
				if uplink == arpValues.Port {
					isUplink = true
				}
			}

			if !isUplink {
				fmt.Printf("*** Found IP at switch [%s, %s] w/ values [MAC_NUM: %s, PORT: %d]\n", switchIP, switchDescription, aMACnum, arpValues.Port)
			}
			IPscan[switchIP] = SwitchInfo{Description: switchDescription, MatchingPort: arpValues.Port, UplinkPort: isUplink}
			isUplink = false
		}
	}

	// Roger finished thread
	defer wg.Done()
}

// ScanIP loops every switch on the network looking for an IP matching
func ScanIP(ipToFind string, N Network) SwitchScan {
	// Get the master table
	mainSwitchArpTable := GetMasterIPmacTable(N)

	// Prepare IP check output
	IPscan := make(SwitchScan)

	// macToFind := mainSwitchArpTable[ipToFind].MACaddress
	// goDebug.Print("macToFind", macToFind)
	macNumToFind := mainSwitchArpTable[ipToFind].MACaddressNumeric
	// ipToFindVLAN := mainSwitchArpTable[ipToFind].VLAN
	// ipToFindMACaddress := mainSwitchArpTable[ipToFind].MACaddress
	// goDebug.Print("macNumToFind", macNumToFind)

	// Init gorutine sync
	wg.Add(len(N.Nodes))

	// Launch concurrent threads
	for _, node := range N.Nodes {
		fmt.Printf("Querying switch %s\n", node.IP)
		if toggleConcurrency {
			go scanIPonSwitch(macNumToFind, node.IP, node.Community, node.Description, node.Uplinks, IPscan)
		} else {
			scanIPonSwitch(macNumToFind, node.IP, node.Community, node.Description, node.Uplinks, IPscan)
		}
	}

	// Threads are running ...
	if toggleConcurrency {
		wg.Wait()
	}

	return IPscan
}
