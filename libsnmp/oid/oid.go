package libsnmp

import (
	"fmt"
	"time"

	"github.com/k-sone/snmpgo"
)

/***********************/
/* Global variables ****/
/***********************/

/***********************/
/* SNMP functions ******/
/***********************/

// OIDs outputs are JSON-encoded and comply w/ these structures

// Avariable is the standard way an OID delivers values and formats
type Avariable struct {
	Type  string
	Value string
}

// AnOID is a key/value pair
type AnOID struct {
	Oid      string
	Variable Avariable
}

// GetOID query just one OID
func GetOID(IP string, _Community string, OID string) string {
	// fmt.Printf("GetOID: IP, _Community, OID: %s, %s, %s\n", IP, _Community, OID)

	snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:   snmpgo.V2c,
		Address:   fmt.Sprintf("%s:161", IP),
		Retries:   1,
		Community: _Community,
		Timeout:   time.Duration(500) * time.Millisecond,
	})
	if err != nil {
		// Failed to create snmpgo.SNMP object
		fmt.Println(err)
		return ""
	}

	oids, err := snmpgo.NewOids([]string{
		OID,
	})
	if err != nil {
		// Failed to parse Oids
		fmt.Println(err)
		return ""
	}

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		fmt.Println(err)
		return ""
	}
	defer snmp.Close()

	pdu, err := snmp.GetRequest(oids)
	if err != nil {
		// Failed to request
		fmt.Println(err)
		return ""
	}
	if pdu.ErrorStatus() != snmpgo.NoError {
		// Received an error from the agent
		fmt.Println(pdu.ErrorStatus(), pdu.ErrorIndex())
	}

	// get VarBind list
	// fmt.Printf("DEBUG: len(pdu.VarBinds()): %d\n", len(pdu.VarBinds()))
	// goDebug.Print("pdu.VarBinds()", pdu.VarBinds())

	// select a VarBind
	// fmt.Printf("DEBUG: pdu.VarBinds(): %s\n", pdu.VarBinds().String())
	// fmt.Printf("pdu.VarBinds().MatchOid(oids[0])): %+v\n", pdu.VarBinds().MatchOid(oids[0]))

	return pdu.VarBinds()[0].String()
}

// GetOIDsubtree query just one OID subtree, snmpwalk
func GetOIDsubtree(IP string, _Community string, OID string) []string {
	var output []string

	// fmt.Printf("GetOIDsubtree: IP, _Community, OID: %s, %s, %s\n", IP, _Community, OID)

	snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:   snmpgo.V2c,
		Address:   fmt.Sprintf("%s:161", IP),
		Retries:   1,
		Community: _Community,
		Timeout:   time.Duration(500) * time.Millisecond,
	})
	if err != nil {
		// Failed to create snmpgo.SNMP object
		fmt.Println(err)
		return output
	}

	oids, err := snmpgo.NewOids([]string{
		OID,
	})
	if err != nil {
		// Failed to parse Oids
		fmt.Println(err)
		return output
	}

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		fmt.Println(err)
		return output
	}
	defer snmp.Close()

	pdu, err := snmp.GetBulkWalk(oids, 0, 10)
	if err != nil {
		// Failed to request
		fmt.Println(err)
		return output
	}
	if pdu.ErrorStatus() != snmpgo.NoError {
		// Received an error from the agent
		fmt.Println(pdu.ErrorStatus(), pdu.ErrorIndex())
	}

	// get VarBind list
	// fmt.Printf("DEBUG: len(pdu.VarBinds()): %d\n", len(pdu.VarBinds()))
	// goDebug.Print("pdu.VarBinds()", pdu.VarBinds())

	// select a VarBind
	// fmt.Printf("DEBUG: pdu.VarBinds(): %+v\n", pdu.VarBinds())
	// fmt.Printf("pdu.VarBinds().MatchOid(oids[0])): %+v\n", pdu.VarBinds().MatchOid(oids[0]))

	for _, r := range pdu.VarBinds() {
		// fmt.Printf("DEBUG: r: %+v\n", r)
		output = append(output, r.String())
	}

	return output
}
