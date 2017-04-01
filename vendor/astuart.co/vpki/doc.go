// Package vpki provides a layer of abstraction between the golang stdlib
// crypto primitives and common crypto uses (e.g. serving HTTPS) and the
// functionality provided by Vault. Internally, the library generates private
// keys locally and sends CSRs to the vault server, so that private keys are
// never transmitted.
package vpki // import "astuart.co/vpki"
