[![GoDoc](https://godoc.org/github.com/trustelem/ldap?status.svg)](https://godoc.org/github.com/trustelem/ldap)
[![Build Status](https://travis-ci.org/trustelem/ldap.svg)](https://travis-ci.org/trustelem/ldap)

# Basic LDAP v3 functionality for the GO programming language.

## Install

For the latest version use:

    go get github.com/trustelem/ldap

Import the latest version with:

    import "github.com/trustelem/ldap"

## Required Libraries:

 - github.com/go-asn1-ber/asn1-ber

## Features:

 - Connecting to LDAP server (non-TLS, TLS, STARTTLS)
 - Binding to LDAP server
 - Searching for entries
 - Filter Compile / Decompile
 - Paging Search Results
 - Modify Requests / Responses
 - Add Requests / Responses
 - Delete Requests / Responses
 - Modify DN Requests / Responses

## Examples:

 - search
 - modify

## Contributing:

Bug reports and pull requests are welcome!

Before submitting a pull request, please make sure tests and verification scripts pass:
```
make all
```

To set up a pre-push hook to run the tests and verify scripts before pushing:
```
ln -s ../../.githooks/pre-push .git/hooks/pre-push
```

---
The Go gopher was designed by Renee French. (http://reneefrench.blogspot.com/)
The design is licensed under the Creative Commons 3.0 Attributions license.
Read this article for more details: http://blog.golang.org/gopher
