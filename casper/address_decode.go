package casper

import (
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcdrivers/owkeychain"
	"github.com/blocktree/openwallet/v2/common"
	"github.com/blocktree/openwallet/v2/openwallet"
)

//AddressDecoderV2
type AddressDecoderV2 struct {
	*openwallet.AddressDecoderV2Base
}

//AddressDecode 地址解析
func (dec *AddressDecoderV2) AddressDecode(addr string, opts ...interface{}) ([]byte, error) {

	if len(addr) < 66 || len(addr) > 68 {
		return nil, fmt.Errorf("address length is invalid")
	}

	bytes, err := hex.DecodeString(addr)
	if err != nil {
		return nil, err
	}

	prefix := bytes[0]
	switch prefix {
	case ED25519_TAG:
		return bytes[1:], nil
	case SECP256K1_TAG:
		return bytes[1:], nil
	default:
		return nil, fmt.Errorf("address decode failed")
	}
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
	case ED25519_TAG:
		hash = append([]byte{0x01}, pub...)
	case SECP256K1_TAG:
		hash = append([]byte{0x02}, pub...)
	}
	return hex.EncodeToString(hash), nil
}

// AddressVerify 地址校验
func (dec *AddressDecoderV2) AddressVerify(address string, opts ...interface{}) bool {
	_, err := dec.AddressDecode(address)
	if err != nil {
		return false
	}
	return true
}

// CustomCreateAddress 创建账户地址
func (dec *AddressDecoderV2) CustomCreateAddress(account *openwallet.AssetsAccount, newIndex uint64) (*openwallet.Address, error) {

	if len(account.HDPath) == 0 {
		return nil, fmt.Errorf("hdPath is empty")
	}
	hdPath := fmt.Sprintf("%s/%d/%d", account.HDPath, 0, newIndex)
	var newKeys = make([][]byte, 0) //通过多个拥有者公钥生成地址
	for _, pub := range account.OwnerKeys {
		if len(pub) == 0 {
			continue
		}
		pubkey, err := owkeychain.OWDecode(pub)
		if err != nil {
			return nil, err
		}
		start, err := pubkey.GenPublicChild(0)
		newKey, err := start.GenPublicChild(uint32(newIndex))
		newKeys = append(newKeys, newKey.GetPublicKeyBytes())
	}
	var err error
	var address, publicKey string

	address, err = dec.AddressEncode(newKeys[0])
	//address, err = decoder.PublicKeyToAddress(newKeys[0], false)
	if err != nil {
		return nil, err
	}
	publicKey = hex.EncodeToString(newKeys[0])

	if len(address) == 0 {
		return nil, fmt.Errorf("create address content error")
	}
	newAddr := &openwallet.Address{
		AccountID: account.AccountID,
		Symbol:    account.Symbol,
		Index:     newIndex,
		Address:   address,
		Balance:   "0",
		WatchOnly: false,
		PublicKey: publicKey,
		Alias:     "",
		Tag:       "",
		HDPath:    hdPath,
		IsChange:  common.NewString(0).Bool(),
		IsMemo:    true,
		Memo:      PublicKeyToHash(publicKey, ED25519_TAG),
	}

	return newAddr, nil

}

// SupportCustomCreateAddressFunction 支持创建地址实现
func (dec *AddressDecoderV2) SupportCustomCreateAddressFunction() bool {
	return true
}
