package vpki

import "fmt"

// VaultError is an error originating from a vault client. Errors coming from
// the vpki library should be type checked against this error (use a type
// switch)
type VaultError struct {
	Client Client
	Orig   error
}

func (ve *VaultError) Error() string {
	return fmt.Sprintf("%s returned an error: %v", ve.Client.Addr, ve.Orig)
}
