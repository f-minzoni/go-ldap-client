// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"

	"gopkg.in/ldap.v2"
)

type LDAPClient struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(uid=%s)"
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
}

type AddUserAccount struct {
	Username string
	Password string
	OU       string
	UID      int
	GID      int
}

// Connect connects to the ldap backend.
func (lc *LDAPClient) Connect() error {
	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return err
				}
			}
		} else {
			l, err = ldap.DialTLS("tcp", address, &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify,
				ServerName:         lc.ServerName,
			})
			if err != nil {
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}

// Close closes the ldap backend connection.
func (lc *LDAPClient) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

// Authenticate authenticates the user against the ldap backend.
func (lc *LDAPClient) Authenticate(username, password string) (bool, map[string]string, error) {
	err := lc.Connect()
	if err != nil {
		return false, nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return false, nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		return false, nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return false, nil, errors.New("Too many entries returned")
	}

	userDN := sr.Entries[0].DN
	user := map[string]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		return false, user, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return true, user, err
		}
	}

	return true, user, nil
}

// GetGroupsOfUser returns the group for a user.
func (lc *LDAPClient) GetGroupsOfUser(username string) ([]string, error) {
	return lc.Filter(fmt.Sprintf(lc.GroupFilter, username), []string{"cn"})
}

// Filter returns the found entries.
func (lc *LDAPClient) Filter(filter string, attributes []string) ([]string, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	result := []string{}
	for _, entry := range sr.Entries {
		for _, attr := range entry.Attributes {
			for _, value := range attr.Values {
				result = append(result, value)
			}
		}
	}
	return result, nil
}

// AddUser persist a new user.
func (lc *LDAPClient) AddUser(username, password, ou string) error {
	err := lc.Connect()
	if err != nil {
		return err
	}

	// First bind with an admin user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return err
		}
	}

	userDN := fmt.Sprintf("cn=%s,ou=%s,%s", username, ou, lc.Base)
	addRequest := ldap.NewAddRequest(userDN)

	addRequest.Attribute("objectClass", []string{"inetOrgPerson"})
	addRequest.Attribute("userPassword", []string{password})
	addRequest.Attribute("sn", []string{username})
	addRequest.Attribute("uid", []string{username})

	return lc.Conn.Add(addRequest)
}

// AddUserAccount persist a new user account.
func (lc *LDAPClient) AddUserAccount(account AddUserAccount) error {
	err := lc.Connect()
	if err != nil {
		return err
	}

	// First bind with an admin user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return err
		}
	}

	userDN := fmt.Sprintf("cn=%s,ou=%s,%s", account.Username, account.OU, lc.Base)
	addRequest := ldap.NewAddRequest(userDN)

	addRequest.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount"})
	addRequest.Attribute("uidNumber", []string{strconv.Itoa(account.UID)})
	addRequest.Attribute("gidNumber", []string{strconv.Itoa(account.GID)})
	addRequest.Attribute("userPassword", []string{account.Password})
	addRequest.Attribute("homeDirectory", []string{"/home/" + account.Username})
	addRequest.Attribute("loginShell", []string{"/bin/bash"})
	addRequest.Attribute("sn", []string{account.Username})
	addRequest.Attribute("uid", []string{account.Username})

	return lc.Conn.Add(addRequest)
}

// ChangeMembers updates the members of a given group.
func (lc *LDAPClient) ChangeMembers(members []string, groupname, ou string) error {
	DN := fmt.Sprintf("cn=%s,ou=%s,%s", groupname, ou, lc.Base)
	return lc.ChangeAttribute(DN, "memberUid", members)
}

// ChangeDescription updates the description of a given OU.
func (lc *LDAPClient) ChangeDescription(description, ou string) error {
	DN := fmt.Sprintf("ou=%s,%s", ou, lc.Base)
	return lc.ChangeAttribute(DN, "description", []string{description})
}

// ChangePassword updates the password of a given user.
func (lc *LDAPClient) ChangePassword(password, username, ou string) error {
	DN := fmt.Sprintf("cn=%s,ou=%s,%s", username, ou, lc.Base)
	return lc.ChangeAttribute(DN, "userPassword", []string{password})
}

// ChangeAttribute updates the attribute values of a given DN.
func (lc *LDAPClient) ChangeAttribute(DN, attribute string, values []string) error {
	err := lc.Connect()
	if err != nil {
		return err
	}

	// First bind with an admin user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return err
		}
	}

	modifyRequest := ldap.NewModifyRequest(DN)
	attr := ldap.PartialAttribute{
		Type: attribute,
		Vals: values,
	}
	attributes := []ldap.PartialAttribute{}
	modifyRequest.ReplaceAttributes = append(attributes, attr)

	return lc.Conn.Modify(modifyRequest)
}
