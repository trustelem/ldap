package ldap

import (
	"errors"
)

// ROOTDSE common attributes
const (
	RootDSEdefaultNamingContext    = "defaultNamingContext"
	RootDSEdnsHostName             = "dnsHostName"
	RootDSEsupportedSASLMechanisms = "supportedSASLMechanisms"
	RootDSEldapServiceName         = "ldapServiceName"
	RootDSEhighestCommittedUSN     = "highestCommittedUSN"
	RootDSEsubschemaSubentry       = "subschemaSubentry"
)

// RootDSE allows to retrieve the RootDSE entry, returning the provided attributes
func (conn *Conn) RootDSE(fields ...string) (*Entry, error) {
	if len(fields) == 0 {
		fields = nil
	}
	// scan root DSE
	search := NewSearchRequest(
		"", // BaseDN
		ScopeBaseObject, NeverDerefAliases, 0, 0, false,
		"(objectclass=*)",
		fields,
		nil)

	res, err := conn.Search(search)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, errors.New("Cannot get RootDSE")
	}
	rootEntry := res.Entries[0]
	return rootEntry, nil
}
