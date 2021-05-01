package casper_addrdec

import (
	"encoding/hex"
	"testing"
)

func TestAddressDecoder_AddressEncode(t *testing.T) {
	pk, _ := hex.DecodeString("96377909058287e15ae2a3df5b77dc0abcd41136bdf8f919d5ffb412777ae475")
	pkAddr, _ := Default.AddressEncode(pk)
	t.Logf("pkAddr: %s", pkAddr)
}

func TestAddressDecoder_AddressDecode(t *testing.T) {
	pkAddr := "9cc6dc915ff164a49e8df6781ad1efb4d6ee0592b49ec74a50b7e3655aa3487f"
	pk, err := Default.AddressDecode(pkAddr)
	if err != nil {
		t.Errorf("AddressDecode failed, err: %v", err)
		return
	}
	t.Logf("pk: %s", hex.EncodeToString(pk))
}
