package main

import (
	"errors"
	"fmt"
	"github.com/msteinert/pam"
	"github.com/nmcclain/asn1-ber"
	"github.com/nmcclain/ldap"
	"log"
	"net"
	"os"
	"os/user"
	"strings"
)

type Backend struct {
	ldap.Binder
	ldap.Searcher
	ldap.Closer
	logger            *log.Logger
	Listen            string
	BaseDN            string
	PAMServiceName    string
	PeopleDN          string
	GroupsDN          string
	BindAdminDN       string
	BindAdminPassword string
}

var logger = log.New(os.Stdout, "", log.LstdFlags)

func main() {
	logger.Println("start")
	l := ldap.NewServer()
	l.EnforceLDAP = true
	var backend = Backend{
		PAMServiceName:    "password-auth",
		logger:            logger,
		Listen:            "127.0.0.1:10389",
		BaseDN:            "dc=example,dc=com",
		PeopleDN:          "ou=people,dc=example,dc=com",
		GroupsDN:          "ou=groups,dc=example,dc=com",
		BindAdminDN:       "uid=user,dc=example,dc=com",
		BindAdminPassword: "password",
	}
	l.BindFunc("", backend)
	l.SearchFunc("", backend)
	l.CloseFunc("", backend)
	if err := l.ListenAndServe(backend.Listen); err != nil {
		backend.logger.Fatalf("LDAP serve failed: %s", err.Error())
	}
}

func (b Backend) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	b.logger.Printf("Bind attempt addr=%s bindDN=%s", conn.RemoteAddr().String(), bindDN)
	if bindDN == b.BindAdminDN {
		if bindSimplePw != b.BindAdminPassword {
			return ldap.LDAPResultInvalidCredentials, errors.New("Password Incorrect")
		}
		return ldap.LDAPResultSuccess, nil
	} else {
		var username string
		if username, err = b.getUserNameFromBindDN(bindDN); err != nil {
			return ldap.LDAPResultInvalidCredentials, err
		}
		if err := PAMAuth(b.PAMServiceName, username, bindSimplePw); err != nil {
			return ldap.LDAPResultInvalidCredentials, err
		}
		return ldap.LDAPResultSuccess, nil
	}
}

func (b Backend) Search(bindDN string, req ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	b.logger.Printf("Search bindDN=%s baseDN=%s filter=%s addr=%s", bindDN, req.BaseDN, req.Filter, conn.RemoteAddr().String())
	filterObjectClass, err := ldap.GetFilterObjectClass(req.Filter)
	if err != nil {
		b.logger.Printf("Search Error: error parsing ObjectClass: %s", req.Filter)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing ObjectClass: %s", req.Filter)
	}
	var username string
	var user_entity_name string
	if filterObjectClass == "posixaccount" || filterObjectClass == "" {
		user_entity_name = "uid"
	} else if filterObjectClass == "posixgroup" {
		user_entity_name = "memberUid"
	} else {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Filter does not contain objectclass=posixaccount nor objectclass=posixgroup")
	}

	if bindDN == b.BindAdminDN {
		filterUid, err := GetFilterEntity(user_entity_name, req.Filter)
		if err != nil {
			b.logger.Printf("Search Error: error find condition uid: %s", req.Filter)
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error find condition uid: %s", req.Filter)
		}
		username = filterUid
	} else {
		if username, err = b.getUserNameFromBindDN(bindDN); err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
		}
	}
	var entry *ldap.Entry
	if filterObjectClass == "posixaccount" || filterObjectClass == "" {
		if entry, err = b.makeSearchEntryAccount("cn="+username+","+b.PeopleDN, username); err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
		}
	} else if filterObjectClass == "posixgroup" {
		if entry, err = b.makeSearchEntryGroup(b.GroupsDN, username); err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
		}
	} else {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Filter does not contain objectclass=posixaccount nor objectclass=posixgroup")
	}
	return ldap.ServerSearchResult{[]*ldap.Entry{entry}, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil

	return ldap.ServerSearchResult{make([]*ldap.Entry, 0), []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

func (b Backend) Close(bindDN string, conn net.Conn) (err error) {
	b.logger.Printf("Close addr=%s bindDN=%s", conn.RemoteAddr().String(), bindDN)
	return nil
}

func PAMAuth(serviceName, userName, passwd string) error {
	t, err := pam.StartFunc(serviceName, userName, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return passwd, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		return "", errors.New("Unrecognized PAM message style")
	})

	if err != nil {
		return err
	}

	if err = t.Authenticate(0); err != nil {
		return err
	}

	return nil
}

func (b Backend) getUserNameFromBindDN(bindDN string) (username string, err error) {
	if bindDN == "" {
		return "", errors.New("bindDN not specified")
	}
	if !strings.HasSuffix(bindDN, ","+b.PeopleDN) {
		return "", errors.New("bindDN not matched")
	}
	rest := strings.TrimSuffix(bindDN, ","+b.PeopleDN)
	if rest == "" {
		return "", errors.New("bindDN format error")
	}
	if strings.Contains(rest, ",") {
		return "", errors.New("bindDN has too much entities")
	}
	if strings.HasPrefix(rest, "uid=") {
		username = strings.TrimPrefix(rest, "uid=")
	} else if strings.HasPrefix(rest, "cn=") {
		username = strings.TrimPrefix(rest, "cn=")
	} else {
		return "", errors.New("bindDN contains no cn/uid entry")
	}
	return username, nil
}

func (b Backend) makeSearchEntryAccount(dn string, username string) (entry *ldap.Entry, err error) {
	attrs := []*ldap.EntryAttribute{}
	var u *user.User
	if u, err = user.Lookup(username); err != nil {
		return entry, err
	}
	attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"posixAccount"}})
	attrs = append(attrs, &ldap.EntryAttribute{"cn", []string{username}})
	attrs = append(attrs, &ldap.EntryAttribute{"uid", []string{username}})
	attrs = append(attrs, &ldap.EntryAttribute{"uidNumber", []string{u.Uid}})
	attrs = append(attrs, &ldap.EntryAttribute{"givenName", []string{u.Name}})
	attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{u.Gid}})
	attrs = append(attrs, &ldap.EntryAttribute{"homeDirectory", []string{u.HomeDir}})

	entry = &ldap.Entry{dn, attrs}
	return entry, nil
}

func (b Backend) makeSearchEntryGroup(basedn string, username string) (entry *ldap.Entry, err error) {
	attrs := []*ldap.EntryAttribute{}
	var (
		u *user.User
		g *user.Group
	)
	if u, err = user.Lookup(username); err != nil {
		return entry, err
	}
	if g, err = user.LookupGroupId(u.Gid); err != nil {
		return entry, err
	}

	attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"posixGroup"}})
	attrs = append(attrs, &ldap.EntryAttribute{"cn", []string{g.Name}})
	attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{u.Gid}})
	attrs = append(attrs, &ldap.EntryAttribute{"memberUid", []string{username}})

	dn := "cn=" + g.Name + "," + basedn
	entry = &ldap.Entry{dn, attrs}
	return entry, nil
}

func GetFilterEntity(entity string, filter string) (string, error) {
	f, err := ldap.CompileFilter(filter)
	if err != nil {
		return "", err
	}
	return parseFilterEntity(entity, f)
}

func parseFilterEntity(entity string, f *ber.Packet) (string, error) {
	foundEntity := ""
	switch ldap.FilterMap[f.Tag] {
	case "Equality Match":
		if len(f.Children) != 2 {
			return "", errors.New("Equality match must have only two children")
		}
		attribute := strings.ToLower(f.Children[0].Value.(string))
		value := f.Children[1].Value.(string)
		if attribute == entity {
			foundEntity = strings.ToLower(value)
		}
	case "And":
		for _, child := range f.Children {
			subType, err := parseFilterEntity(entity, child)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				foundEntity = subType
			}
		}
	case "Or":
		for _, child := range f.Children {
			subType, err := parseFilterEntity(entity, child)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				foundEntity = subType
			}
		}
	case "Not":
		if len(f.Children) != 1 {
			return "", errors.New("Not filter must have only one child")
		}
		subType, err := parseFilterEntity(entity, f.Children[0])
		if err != nil {
			return "", err
		}
		if len(subType) > 0 {
			foundEntity = subType
		}

	}
	return strings.ToLower(foundEntity), nil
}
