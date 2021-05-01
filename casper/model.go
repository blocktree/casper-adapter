package casper

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/blocktree/openwallet/v2/common"
	"github.com/blocktree/openwallet/v2/openwallet"
	"github.com/tidwall/gjson"
	"math/big"
	"time"
)

const (
	BlockIdentifierLastBlock = uint8(0)
	BlockIdentifierHeight    = uint8(1)
	BlockIdentifierHash      = uint8(2)
)

type Block struct {
	Hash              string
	StateRootHash     string
	Previousblockhash string
	Height            uint64
	Version           string
	Time              uint64
	Fork              bool
	TransferHashes    []string
}

func NewBlock(json gjson.Result) *Block {
	obj := &Block{}
	//解析json
	obj.Height = gjson.Get(json.Raw, "header.height").Uint()
	obj.Hash = gjson.Get(json.Raw, "hash").String()
	obj.StateRootHash = gjson.Get(json.Raw, "header.state_root_hash").String()
	obj.Previousblockhash = gjson.Get(json.Raw, "header.parent_hash").String()
	obj.Version = gjson.Get(json.Raw, "header.protocol_version").String()
	timeVal, _ := time.Parse(time.RFC3339, gjson.Get(json.Raw, "header.timestamp").String())
	obj.Time = uint64(timeVal.Unix())
	transactions := make([]string, 0)
	for _, tx := range gjson.Get(json.Raw, "body.transfer_hashes").Array() {
		transactions = append(transactions, tx.String())
	}

	obj.TransferHashes = transactions

	return obj
}

//BlockHeader 区块链头
func (b *Block) BlockHeader(symbol string) *openwallet.BlockHeader {

	obj := openwallet.BlockHeader{}
	//解析json
	obj.Hash = b.Hash
	obj.Merkleroot = b.StateRootHash
	obj.Previousblockhash = b.Previousblockhash
	obj.Height = b.Height
	//obj.Version = b.Version
	obj.Time = b.Time
	obj.Symbol = symbol

	return &obj
}

type Header struct {
	Account      *PublicKey
	BodyHash     []byte
	ChainName    string
	Dependencies []ToBytes
	GasPrice     uint64
	Timestamp    int64
	Ttl          uint64
}

func (header *Header) MarshalJSON() ([]byte, error) {
	j := make(map[string]interface{}, 0)
	j["account"] = ToAccountHex(hex.EncodeToString(header.Account.RawPublicKey))
	j["body_hash"] = hex.EncodeToString(header.BodyHash)
	j["chain_name"] = header.ChainName
	j["dependencies"] = header.Dependencies
	j["gas_price"] = header.GasPrice
	j["timestamp"] = time.Unix(header.Timestamp, 0).UTC().Format("2006-01-02T15:04:05.000Z")
	j["ttl"] = fmt.Sprintf("%dms", header.Ttl)
	return json.Marshal(j)
}

type Approval struct {
	Signature string `json:"signature"`
	Signer    string `json:"signer"`
}

type NumberCoder struct {
	BitSize uint64
	Signed  bool
	Val     *big.Int
	Name    string
}

func (number *NumberCoder) ToBytes() []byte {
	return toBytesNumber(number.BitSize, number.Signed, number.Val)
}

type CLValue struct {
	ClType uint8
	Parsed interface{}
	Value  CLTypedAndToBytes
	Bytes  string
}

func (clv *CLValue) ToBytes() []byte {
	body := toBytesArrayU8(clv.Value.ToBytes())
	body = append(body, clv.Value.ClTypeToBytes()...)
	return body
}

func (clv *CLValue) MarshalJSON() ([]byte, error) {
	j := make(map[string]interface{}, 0)
	j["cl_type"] = clv.Value.ClTypeToJson()
	j["bytes"] = clv.Bytes
	//j["parsed"] = clv.Parsed
	j["parsed"] = "null"
	return json.Marshal(j)
}

func NewCLValue(value CLTypedAndToBytes) *CLValue {
	cv := &CLValue{
		ClType: value.ClType(),
		Value:  value,
		Bytes:  hex.EncodeToString(value.ToBytes()),
	}
	return cv
}

type U64 struct {
	NumberCoder
}

func (u64 *U64) ClType() uint8 {
	return CLTypeU64
}

func (u64 *U64) ClTypeToBytes() []byte {
	return []byte{u64.ClType()}
}

func (u64 *U64) ClTypeToJson() interface{} {
	return "U64"
}

func NewU64(amount string) *U64 {

	number := &U64{
		NumberCoder{
			BitSize: 64,
			Signed:  false,
			Val:     common.StringNumToBigIntWithExp(amount, 0),
			Name:    "u64",
		},
	}
	return number
}

type U512 struct {
	NumberCoder
}

func (u512 *U512) ClType() uint8 {
	return CLTypeU512
}

func (u512 *U512) ClTypeToBytes() []byte {
	return []byte{u512.ClType()}
}

func (u512 *U512) ClTypeToJson() interface{} {
	return "U512"
}

func FromU512(amount string) *CLValue {

	number := &U512{
		NumberCoder{
			BitSize: 512,
			Signed:  false,
			Val:     common.StringNumToBigIntWithExp(amount, 0),
			Name:    "u512",
		},
	}
	cv := NewCLValue(number)
	return cv
}

type ByteArrayValue struct {
	RawBytes []byte
}

func (bav *ByteArrayValue) ClType() uint8 {
	return CLTypeByteArray
}

func (bav *ByteArrayValue) ToBytes() []byte {
	return toBytesBytesArray(bav.RawBytes)
}

func (bav *ByteArrayValue) ClTypeToBytes() []byte {
	return append([]byte{bav.ClType()}, toBytesU32(uint64(len(bav.RawBytes)))...)
}

func (bav *ByteArrayValue) ClTypeToJson() interface{} {
	return map[string]uint64{
		"ByteArray": uint64(len(bav.RawBytes)),
	}
}

func FromByteArray(bytes []byte) *CLValue {
	value := &ByteArrayValue{RawBytes: bytes}
	cv := NewCLValue(value)
	return cv
}

type Option struct {
	Inner CLTypedAndToBytes
}

func (op *Option) ClType() uint8 {
	return CLTypeOption
}

func (op *Option) ToBytes() []byte {

	if op.Inner == nil {
		return []byte{0}
	} else {
		return append([]byte{1}, op.Inner.ToBytes()...)
	}
}

func (op *Option) ClTypeToBytes() []byte {
	return append([]byte{op.ClType()}, op.Inner.ClTypeToBytes()...)
}

func (op *Option) ClTypeToJson() interface{} {
	return map[string]interface{}{
		"Option": op.Inner.ClTypeToJson(),
	}
}

func FromOption(t CLTypedAndToBytes, innerType uint8) *CLValue {
	value := &Option{Inner: t}
	cv := NewCLValue(value)
	return cv
}

type NamedArg struct {
	Name  string
	Value *CLValue
}

func (arg *NamedArg) ToBytes() []byte {
	name := toBytesString(arg.Name)
	value := arg.Value.ToBytes()
	return append(name, value...)
}

type RuntimeArgs struct {
	args []*NamedArg
}

func (ra *RuntimeArgs) ToBytes() []byte {
	vec := make([]ToBytes, 0)
	for _, a := range ra.args {
		vec = append(vec, a)
	}
	return toBytesVec(vec)
}

func (ra *RuntimeArgs) Insert(name string, value *CLValue) {
	ra.args = append(ra.args, &NamedArg{
		Name:  name,
		Value: value,
	})
}

func (ra *RuntimeArgs) MarshalJSON() ([]byte, error) {
	j := make([]interface{}, 0)

	for _, arg := range ra.args {
		arr := []interface{}{
			arg.Name,
			arg.Value,
		}
		j = append(j, arr)
	}
	return json.Marshal(j)
}

func NewRuntimeArgs() *RuntimeArgs {
	return &RuntimeArgs{args: make([]*NamedArg, 0)}
}

type Payment struct {
	Amount      string
	ModuleBytes []byte
	Args        *RuntimeArgs
}

func (p *Payment) Tag() uint8 {
	return 0
}

func (p *Payment) MarshalJSON() ([]byte, error) {
	j := make(map[string]interface{}, 0)
	j["module_bytes"] = hex.EncodeToString(p.ModuleBytes)
	j["args"] = p.Args

	return json.Marshal(map[string]interface{}{
		"ModuleBytes": j,
	})
}

func StandardPayment(amount string) *Payment {
	p := &Payment{
		Amount: amount,
		Args:   NewRuntimeArgs(),
	}
	p.Args.Insert("amount", FromU512(amount))
	return p
}

func (p *Payment) ToBytes() []byte {

	body := make([]byte, 0)
	body = append(body, p.Tag())
	body = append(body, toBytesArrayU8(p.ModuleBytes)...)
	body = append(body, toBytesBytesArray(p.Args.ToBytes())...)

	return body
}

type Transfer struct {
	Amount      string
	Target      string
	ID          string
	Args        *RuntimeArgs
	From        string
	To          string
	DeployHash  string
	Source      string
	Gas         string
	BlockHeight uint64
	BlockHash   string
}

func (t *Transfer) Tag() uint8 {
	return 5
}

func (t *Transfer) ToBytes() []byte {

	body := make([]byte, 0)
	body = append(body, t.Tag())
	body = append(body, toBytesBytesArray(t.Args.ToBytes())...)

	return body
}

func (t *Transfer) MarshalJSON() ([]byte, error) {
	j := make(map[string]interface{}, 0)
	j["args"] = t.Args
	return json.Marshal(map[string]interface{}{
		"Transfer": j,
	})
}

func NewTransfer(amount string, target []byte, id string) *Transfer {

	t := &Transfer{
		Amount: amount,
		Target: hex.EncodeToString(target),
		Args:   NewRuntimeArgs(),
	}

	t.Args.Insert("amount", FromU512(amount))
	t.Args.Insert("target", FromByteArray(target))
	if id == "" {
		t.Args.Insert("id", FromOption(nil, CLTypeU64))
	} else {
		t.Args.Insert("id", FromOption(NewU64(id), CLTypeU64))
	}

	return t
}

type PublicKey struct {
	RawPublicKey []byte
	Tag          uint8
}

func (pk *PublicKey) ClType() uint8 {
	return CLTypePublicKey
}

func (pk *PublicKey) ToBytes() []byte {
	return append([]byte{pk.Tag}, toBytesBytesArray(pk.RawPublicKey)...)
}

func (pk *PublicKey) ClTypeToBytes() []byte {
	return []byte{pk.ClType()}
}

func (pk *PublicKey) ClTypeToJson() interface{} {
	return "PublicKey"
}

type Deploy struct {
	Approvals []*Approval `json:"approvals"`
	Hash      string      `json:"hash"`
	Header    *Header     `json:"header"`
	Payment   *Payment
	Transfer  *Transfer `json:"session"`
}

func (deploy *Deploy) MarshalJSON() ([]byte, error) {
	j := make(map[string]interface{}, 0)
	j["hash"] = deploy.Hash
	j["header"] = deploy.Header
	j["payment"] = deploy.Payment
	j["session"] = deploy.Transfer
	j["approvals"] = deploy.Approvals
	return json.Marshal(j)
}

func serializeBody(payment *Payment, transfer *Transfer) []byte {
	return append(payment.ToBytes(), transfer.ToBytes()...)
}

func serializeHeader(header *Header) []byte {
	//log.Infof("header.Timestamp.UnixNano() = %d", header.Timestamp*1000)
	body := make([]byte, 0)
	body = append(body, header.Account.ToBytes()...)
	body = append(body, toBytesNumber(64, false, big.NewInt(header.Timestamp*1000))...)
	body = append(body, toBytesNumber(64, false, new(big.Int).SetUint64(header.Ttl))...)
	body = append(body, toBytesNumber(64, false, new(big.Int).SetUint64(header.GasPrice))...)
	body = append(body, toBytesBytesArray(header.BodyHash)...)
	body = append(body, toBytesVec(header.Dependencies)...)
	body = append(body, toBytesString(header.ChainName)...)

	return body
}

//func DeployFromJSON(data []byte) (*Deploy, error) {
//	//sender, to, amount, fee, id, timestamp
//
//	j := gjson.ParseBytes(data)
//	hash := j.Get("hash").String()
//	sender := j.Get("header.account").String()
//	if len(sender) < 66 {
//		return nil, fmt.Errorf("header.account decode failed")
//	}
//	sender = sender[2:]
//	to := ""
//	if _, v := range j.Get("session.Transfer.args").Array() {
//
//	}
//	return nil, nil
//}
