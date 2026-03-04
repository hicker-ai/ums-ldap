package main

import "github.com/qinzj/ums-ldap/cmd"

// @title           Claude Demo API
// @version         1.0
// @description     User management system with LDAP server support.

// @host            localhost:8080
// @BasePath        /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT Bearer token

func main() {
	cmd.Execute()
}
