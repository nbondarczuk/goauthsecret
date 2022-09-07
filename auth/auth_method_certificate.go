package auth

import (
	"fmt"
)

type AuthMethodCertificate struct {
	Claim
	Permit
}

func NewAuthMethodCertificate(clm Claim) (AuthMethodCertificate, error) {
	panic(fmt.Sprintf("Not implemented yet"))
}

func (m AuthMethodCertificate) Token() string {
	return m.Permit.token
}
