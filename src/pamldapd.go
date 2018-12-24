package main

import (
	"encoding/json"
	"errors"
	"flag"
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
	PAMServiceName    string
	PeopleDN          string
	GroupsDN          string
	BindAdminDN       string
	BindAdminPassword string
}

func main() {
	var configfile = flag.String("c", "pamldapd.json", "Configuration file")
	var logfile = flag.String("l", "", "Log file (STDOUT if blank)")
	flag.Parse()
	var backend = Backend{}
	{
		confighandle, err := os.Open(*configfile)
		if err != nil {
			fmt.Printf("Could not read: %s\n", err)
			os.Exit(1)
		}
		decoder := json.NewDecoder(confighandle)
		if err := decoder.Decode(&backend); err != nil {
			fmt.Printf("Could not decode configuration configfile %s: %s\n", *configfile, err)
			confighandle.Close()
			os.Exit(1)
		}
		confighandle.Close()
	}
	if *logfile == "" {
		backend.logger = log.New(os.Stdout, "", log.LstdFlags)
	} else {
		loghandle, err := os.OpenFile(*logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Printf("Could not open log file: %s\n", err)
			os.Exit(1)
		}
		defer loghandle.Close()
		log.SetOutput(loghandle)
		backend.logger = log.New(loghandle, "", log.LstdFlags)
	}

	current_user, err := user.Current()
	if err != nil {
		fmt.Printf("Could not get current user: %s\n", err)
		os.Exit(1)
	}
	if current_user.Uid != "0" {
		backend.logger.Printf("WARNING: PAM authentication will fail because not running as root user")
	}

	l := ldap.NewServer()
	l.EnforceLDAP = true
	l.BindFunc("", backend)
	l.SearchFunc("", backend)
	l.CloseFunc("", backend)
	backend.logger.Printf("LDAP server listen: %s", backend.Listen)
	if err := l.ListenAndServe(backend.Listen); err != nil {
		backend.logger.Printf("LDAP server listen failed: %s", err.Error())
		os.Exit(1)
	}
}

func (b Backend) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	var logger_title = fmt.Sprintf("Bind addr=%s bindDN=%s", conn.RemoteAddr().String(), bindDN)
	b.logger.Printf("%s begin", logger_title)
	if bindDN == b.BindAdminDN {
		if bindSimplePw != b.BindAdminPassword {
			return ldap.LDAPResultInvalidCredentials, errors.New("Password Incorrect")
		}
		b.logger.Printf("%s success as administrator", logger_title)
		return ldap.LDAPResultSuccess, nil
	} else {
		var username string
		if username, err = b.getUserNameFromBindDN(bindDN); err != nil {
			return ldap.LDAPResultInvalidCredentials, err
		}
		if err := PAMAuth(b.PAMServiceName, username, bindSimplePw); err != nil {
			return ldap.LDAPResultInvalidCredentials, err
		}
		b.logger.Printf("%s success as normal user", logger_title)
		return ldap.LDAPResultSuccess, nil
	}
}

func (b Backend) Search(bindDN string, req ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	var logger_title = fmt.Sprintf("Search bindDN=%s baseDN=%s filter=%s addr=%s", bindDN, req.BaseDN, req.Filter, conn.RemoteAddr().String())
	b.logger.Printf("%s begin", logger_title)
	filterObjectClass, err := ldap.GetFilterObjectClass(req.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("%s error parsing ObjectClass: %s", logger_title, req.Filter)
	}
	var username string
	var user_entity_name string
	if filterObjectClass == "posixaccount" || filterObjectClass == "" {
		user_entity_name = "uid"
	} else if filterObjectClass == "posixgroup" {
		user_entity_name = "memberUid"
	} else {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("%s error: Filter does not contain objectclass=posixaccount nor objectclass=posixgroup", logger_title)
	}

	if bindDN == b.BindAdminDN {
		filterUid, err := GetFilterEntity(user_entity_name, req.Filter)
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("%s error find condition uid: %s", logger_title, req.Filter)
		}
		if binddn_username, err := b.getUserNameFromBaseDN(req.BaseDN); err == nil {
			username = binddn_username
		} else {
			username = filterUid
		}
	} else {
		if username, err = b.getUserNameFromBindDN(req.BaseDN); err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
		}
	}
	if req.BaseDN == "" {
		return ldap.ServerSearchResult{make([]*ldap.Entry, 0), []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
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
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("%s error: Filter does not contain objectclass=posixaccount nor objectclass=posixgroup", logger_title)
	}
	return ldap.ServerSearchResult{[]*ldap.Entry{entry}, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil

	return ldap.ServerSearchResult{make([]*ldap.Entry, 0), []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

func (b Backend) Close(bindDN string, conn net.Conn) (err error) {
	b.logger.Printf("Close addr=%s", conn.RemoteAddr().String())
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

func (b Backend) getUserNameFromBaseDN(baseDN string) (username string, err error) {
	if baseDN == "" {
		return "", errors.New("baseDN not specified")
	}
	if !strings.HasSuffix(baseDN, ","+b.PeopleDN) {
		return "", errors.New("baseDN not matched")
	}
	rest := strings.TrimSuffix(baseDN, ","+b.PeopleDN)
	if rest == "" {
		return "", errors.New("baseDN format error")
	}
	if strings.Contains(rest, ",") {
		return "", errors.New("baseDN has too much entities")
	}
	if strings.HasPrefix(rest, "uid=") {
		username = strings.TrimPrefix(rest, "uid=")
	} else if strings.HasPrefix(rest, "cn=") {
		username = strings.TrimPrefix(rest, "cn=")
	} else {
		return "", errors.New("baseDN contains no cn/uid entry")
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
