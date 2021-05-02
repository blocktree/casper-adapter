package casper

import (
	"encoding/hex"
	"testing"
)

func TestAddressDecoder_AddressEncode(t *testing.T) {
	addrdec := AddressDecoderV2{}
	pk, _ := hex.DecodeString("96377909058287e15ae2a3df5b77dc0abcd41136bdf8f919d5ffb412777ae475")
	pkAddr, _ := addrdec.AddressEncode(pk)
	t.Logf("pkAddr: %s", pkAddr)
}

func TestAddressDecoder_AddressDecode(t *testing.T) {
	addrdec := AddressDecoderV2{}
	edAddr := "0196377909058287e15ae2a3df5b77dc0abcd41136bdf8f919d5ffb412777ae475"
	edPk, err := addrdec.AddressDecode(edAddr)
	if err != nil {
		t.Errorf("AddressDecode failed, err: %v", err)
		return
	}
	t.Logf("edPk: %s", hex.EncodeToString(edPk))

	secpAddr := "02028b5d31f00bacf667f0822e3f7d66e266a0690b252d59c9474e55a1c6b65fc9dd"
	secpPK, err := addrdec.AddressDecode(secpAddr)
	if err != nil {
		t.Errorf("AddressDecode failed, err: %v", err)
		return
	}
	t.Logf("secpPK: %s", hex.EncodeToString(secpPK))
}
