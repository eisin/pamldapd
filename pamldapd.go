package main

import (
	"errors"
	"fmt"
	"github.com/msteinert/pam"
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
	logger         *log.Logger
	BaseDN         string
	PAMServiceName string
}

var logger = log.New(os.Stdout, "", log.LstdFlags)

func main() {
	logger.Println("start")
	l := ldap.NewServer()
	l.EnforceLDAP = true
	var handler = Backend{
		PAMServiceName: "password-auth",
		logger:         logger,
		BaseDN:         "dc=example,dc=com",
	}
	l.BindFunc("", handler)
	l.SearchFunc("", handler)
	l.CloseFunc("", handler)
	if err := l.ListenAndServe("0.0.0.0:10893"); err != nil {
		logger.Fatalf("LDAP serve failed: %s", err.Error())
	}
}

func (b Backend) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	b.logger.Printf("Bind attempt addr=%s bindDN=%s", conn.RemoteAddr().String(), bindDN)
	var username string
	if username, err = b.getUserNameFromBindDN(bindDN); err != nil {
		return ldap.LDAPResultInvalidCredentials, err
	}
	if err := PAMAuth(b.PAMServiceName, username, bindSimplePw); err != nil {
		return ldap.LDAPResultInvalidCredentials, err
	}
	return ldap.LDAPResultSuccess, nil
}

func (b Backend) Search(bindDN string, req ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	b.logger.Printf("Search bindDN=%s baseDN=%s filter=%s addr=%s", bindDN, req.BaseDN, req.Filter, conn.RemoteAddr().String())
	var username string
	if username, err = b.getUserNameFromBindDN(bindDN); err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
	}
	filterEntity, err := ldap.GetFilterObjectClass(req.Filter)
	if err != nil {
		b.logger.Printf("Search Error: error parsing filter: %s", req.Filter)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing filter: %s", req.Filter)
	}
	if filterEntity == "posixaccount" || filterEntity == "" {
		var entry *ldap.Entry
		if entry, err = b.makeSearchEntry(bindDN, username); err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
		}
		return ldap.ServerSearchResult{[]*ldap.Entry{entry}, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
	} else {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("filter entity could be: posixaccount")
	}

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
	if !strings.HasSuffix(bindDN, ","+b.BaseDN) {
		return "", errors.New("bindDN not matched")
	}
	rest := strings.TrimSuffix(bindDN, ","+b.BaseDN)
	if rest == "" {
		return "", errors.New("bindDN format error")
	}
	if strings.Contains(rest, ",") {
		return "", errors.New("bindDN has too much entities")
	}
	if !strings.HasPrefix(rest, "uid=") {
		return "", errors.New("bindDN contains no uid entry")
	}
	username = strings.TrimPrefix(rest, "uid=")
	return username, nil
}

func (b Backend) makeSearchEntry(dn string, username string) (entry *ldap.Entry, err error) {
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
