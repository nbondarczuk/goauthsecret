package auth

import (
	"fmt"
)

type MethodCertificate struct {
	Claim
	Permit
}

func NewMethodCertificate(clm Claim) (MethodCertificate, error) {
	panic(fmt.Sprintf("Not implemented yet"))
}

func (m MethodCertificate) Token() string {
	return m.Permit.token
}
