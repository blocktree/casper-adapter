package casper_addrdec

import (
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/common"
	"github.com/blocktree/openwallet/v2/openwallet"
)

var (
	Default = AddressDecoderV2{}
)

//AddressDecoderV2
type AddressDecoderV2 struct {
	*openwallet.AddressDecoderV2Base
}

//AddressDecode 地址解析
func (dec *AddressDecoderV2) AddressDecode(addr string, opts ...interface{}) ([]byte, error) {

	if len(addr) != 64 {
		return nil, fmt.Errorf("address length is invalid")
	}

	bytes, err := hex.DecodeString(addr)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

//AddressEncode 地址编码
func (dec *AddressDecoderV2) AddressEncode(pub []byte, opts ...interface{}) (string, error) {
	if len(pub) < 32 {
		return "", fmt.Errorf("publicKey length is invalid")
	}

	var prefix common.String
	if len(opts) > 0 {
		prefix = common.NewString(opts[0])
	}

	hash := make([]byte, 0)
	switch prefix.UInt8(1) {
	case 1:
		hash = append([]byte("ed25519"), 0x00)
	case 2:
		hash = append([]byte("secp256k1"), 0x00)
	}
	hash = append(hash, pub...)
	b2 := owcrypt.Hash(hash, 32, owcrypt.HASH_ALG_BLAKE2B)

	return hex.EncodeToString(b2), nil
}


// AddressVerify 地址校验
func (dec *AddressDecoderV2) AddressVerify(address string, opts ...interface{}) bool {
	_, err := dec.AddressDecode(address)
	if err != nil {
		return false
	}
	return true
}
