
#dapper

![](http://cl.ly/image/2B0w402W1O1T/Image%202013.11.01%205%3A48%3A10%20PM.png)

ldap like a sir

##Usage

	// override default cache timeout (1 minute)
	dapper.CacheExpiration = time.Hour

	// realm name and ldap specifics
	ldap := dapper.New("your.hostname.com", "ldaps://ldap.dapnasty.com", "dc=dapnasty,dc=com")

	// simply wrap an http handler and it will require ldap auth
	http.HandleFunc("/", ldap.RequireAuth(http.FileServer(http.Dir("web"))))
	http.HandleFunc("/status", ldap.RequireAuth(func(w http.ResponseWriter, r *http.Request) {

		fmt.Fprint(w, "authorized")

	}))
