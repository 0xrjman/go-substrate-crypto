package crypto

import (
	"fmt"
	"github.com/JFJun/go-substrate-crypto/crypto/ecdsa"
	"github.com/JFJun/go-substrate-crypto/crypto/sr25519"
	"github.com/JFJun/go-substrate-crypto/ss58"
)

const (
	EcdsaType = iota
	Sr25519Type
)

/*
func: create substrate key
params: curveType
return: priv,pub,error
auth: flynn
date: 2020-09-01
*/
func GenerateSubstrateKey(curveType int) ([]byte, []byte, error) {
	switch curveType {
	case 0:
		return ecdsa.GenerateKey()
	case 1:
		return sr25519.GenerateKey()
	default:
		return nil, nil, fmt.Errorf("unsupport curve type %d to create key", curveType)
	}
}

/*
func: create substrate key
params: priv,curveType
return: pub,error
auth: flynn
date: 2020-09-01
*/
func GenerateSubstrateKeyBySeed(priv []byte, curveType int) ([]byte, error) {
	switch curveType {
	case 0:
		return ecdsa.GenerateKeyBySeed(priv)
	case 1:
		return sr25519.GenerateKeyBySeed(priv)
	default:
		return nil, fmt.Errorf("unsupport curve type %d to create key", curveType)
	}
}

/*
func: create substrate  address
auth: flynn
date: 2020-09-01
*/
func CreateSubstrateAddress(pubKey, prefix []byte) (string, error) {
	return ss58.Encode(pubKey, prefix)
}

/*
func:  substrate  sign
auth: flynn
date: 2020-09-01
*/
func Sign(privateKey, message []byte, curveType int) ([]byte, error) {
	switch curveType {
	case 0:
		return ecdsa.Sign(privateKey, message)
	case 1:
		return sr25519.Sign(privateKey, message)
	default:
		return nil, fmt.Errorf("unsupport curve type %d to sign", curveType)
	}
}
