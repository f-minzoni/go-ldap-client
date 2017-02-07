package ldap_test

import (
	"crypto/md5"
	"encoding/base64"
	"log"

	"github.com/f-minzoni/go-ldap-client"
)

// ExampleLDAPClient_Authenticate shows how a typical application can verify a login attempt
func ExampleLDAPClient_Authenticate() {
	client := &ldap.LDAPClient{
		Base:         "dc=example,dc=com",
		Host:         "ldap.example.com",
		Port:         389,
		UseSSL:       false,
		BindDN:       "uid=readonlysuer,ou=People,dc=example,dc=com",
		BindPassword: "readonlypassword",
		UserFilter:   "(uid=%s)",
		GroupFilter:  "(memberUid=%s)",
		Attributes:   []string{"givenName", "sn", "mail", "uid"},
	}
	defer client.Close()

	ok, user, err := client.Authenticate("username", "password")
	if err != nil {
		log.Fatalf("Error authenticating user %s: %+v", "username", err)
	}
	if !ok {
		log.Fatalf("Authenticating failed for user %s", "username")
	}
	log.Printf("User: %+v", user)

}

// ExampleLDAPClient_GetGroupsOfUser shows how to retrieve user groups
func ExampleLDAPClient_GetGroupsOfUser() {
	client := &ldap.LDAPClient{
		Base:        "dc=example,dc=com",
		Host:        "ldap.example.com",
		Port:        389,
		GroupFilter: "(memberUid=%s)",
	}
	defer client.Close()
	groups, err := client.GetGroupsOfUser("username")
	if err != nil {
		log.Fatalf("Error getting groups for user %s: %+v", "username", err)
	}
	log.Printf("Groups: %+v", groups)
}

// ExampleLDAPClient_GetUsers shows how to retrieve users
func ExampleLDAPClient_GetUsers() {
	client := &ldap.LDAPClient{
		Base: "dc=example,dc=com",
		Host: "ldap.example.com",
		Port: 389,
	}
	defer client.Close()
	users, err := client.Filter("(&(objectClass=organizationalPerson))", []string{"cn"})
	if err != nil {
		log.Fatalf("Error getting users: %+v", err)
	}
	log.Printf("Users: %+v", users)
}

// ExampleLDAPClient_GetGroups shows how to retrieve groups
func ExampleLDAPClient_GetGroups() {
	client := &ldap.LDAPClient{
		Base: "dc=example,dc=com",
		Host: "ldap.example.com",
		Port: 389,
	}
	defer client.Close()
	groups, err := client.Filter("(&(objectClass=posixGroup))", []string{"cn"})
	if err != nil {
		log.Fatalf("Error getting groups: %+v", err)
	}

	log.Printf("Groups: %+v", groups)
}

// ExampleLDAPClient_AddUser shows how to add a new user
func ExampleLDAPClient_AddUser() {
	client := &ldap.LDAPClient{
		Base: "dc=example,dc=com",
		Host: "ldap.example.com",
		Port: 389,
	}
	defer client.Close()

	hash := md5.New()
	hash.Write([]byte("supersecret"))
	b := hash.Sum(nil)
	password := "{MD5}" + base64.StdEncoding.EncodeToString(b)
	err := client.AddUser("newuser", password, "people")
	if err != nil {
		log.Fatalf("Error adding user: %+v", err)
	}
}
