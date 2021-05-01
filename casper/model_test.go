package casper

import (
	"encoding/hex"
	"github.com/blocktree/openwallet/v2/log"
	"testing"
)

func TestCLValue_ToBytes(t *testing.T) {
	// JS: 070000000600a0724e180908
	paymentAmount := FromU512("10000000000000")
	log.Infof("CLValue toBytes: %s", hex.EncodeToString(paymentAmount.ToBytes()))

	// JS: 00000000000100000006000000616d6f756e74070000000600a0724e180908
	payment := StandardPayment("10000000000000")
	log.Infof("Payment toBytes: %s", hex.EncodeToString(payment.ToBytes()))

	// JS: 2200000000000000
	u64 := NewU64("34")
	log.Infof("u64 toBytes: %s", hex.EncodeToString(u64.ToBytes()))

	// JS: 090000000122000000000000000d05
	// GO: 090000000122000000000000000d05
	option_u64 := FromOption(NewU64("34"), CLTypeU64)
	log.Infof("option_u64 toBytes: %s", hex.EncodeToString(option_u64.ToBytes()))

	// JS: 050300000006000000616d6f756e7402000000010a0806000000746172676574200000002326204a1658082975d08b6fbb5597fff206201447a5838ebcb9a1fd97286a110f20000000020000006964090000000122000000000000000d05
	// GO: 050300000006000000616d6f756e7402000000010a0806000000746172676574200000002326204a1658082975d08b6fbb5597fff206201447a5838ebcb9a1fd97286a110f20000000020000006964090000000122000000000000000d05
	accHash, _ := hex.DecodeString("2326204a1658082975d08b6fbb5597fff206201447a5838ebcb9a1fd97286a11")
	session := NewTransfer("10", accHash, "34")
	log.Infof("Transfer Bytes: %s", hex.EncodeToString(session.ToBytes()))

}
