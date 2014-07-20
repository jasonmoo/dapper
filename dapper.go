package dapper

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jasonmoo/acslater"
	ldap "github.com/jasonmoo/go-ldap"
)

type Dapper struct {
	realm     string
	ldap_addr string
	base_dn   string

	cache *acslater.AuthCache
}

var CacheExpiration = time.Minute

func New(realm, ldap_addr, base_dn string) *Dapper {
	return &Dapper{
		realm:     realm,
		ldap_addr: ldap_addr,
		base_dn:   base_dn,

		cache: acslater.NewAuthCache(CacheExpiration),
	}
}

func (d *Dapper) RequireAuth(handler http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(s) != 2 || s[0] != "Basic" {
			unauthorized(w, d.realm)
			return
		}

		token := s[1]

		if d.cache.Check(token) {
			handler(w, r)
			return
		}

		b, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			unauthorized(w, d.realm)
			return
		}
		pair := strings.SplitN(string(b), ":", 2)
		if len(pair) != 2 {
			unauthorized(w, d.realm)
			return
		}

		username, password := pair[0], pair[1]

		conn, err := ldap.DialTLS("tcp", d.ldap_addr)
		if err != nil {
			http.Error(w, "Bad ldap connection", http.StatusBadGateway)
			return
		}

		resp, err := conn.Search(&ldap.SearchRequest{
			BaseDN:     d.base_dn,
			Scope:      ldap.ScopeWholeSubtree,
			Filter:     fmt.Sprintf("(uid=%s)", username),
			Attributes: []string{"dn"},
		})
		if err != nil {
			http.Error(w, "Bad ldap connection", http.StatusBadGateway)
			return
		}

		for _, entry := range resp.Entries {

			if entry.DN != "" {
				if err := conn.Bind(entry.DN, password); err == nil {
					d.cache.Set(token)
					handler(w, r)
					return
				}
			}

		}

		unauthorized(w, d.realm)
	})

}

func unauthorized(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
}
