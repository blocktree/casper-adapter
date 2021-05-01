package casper

import "math/big"

const (
	ED25519_TAG   = uint8(1)
	SECP256K1_TAG = uint8(2)
)
const (
	SignatureAlgorithmEd25519   = "ed25519"
	SignatureAlgorithmSecp256K1 = "secp256k1"
)

const (
	CLTypeBool      = uint8(0)
	CLTypeI32       = uint8(1)
	CLTypeI64       = uint8(2)
	CLTypeU8        = uint8(3)
	CLTypeU32       = uint8(4)
	CLTypeU64       = uint8(5)
	CLTypeU128      = uint8(6)
	CLTypeU256      = uint8(7)
	CLTypeU512      = uint8(8)
	CLTypeUnit      = uint8(9)
	CLTypeString    = uint8(10)
	CLTypeKey       = uint8(11)
	CLTypeURef      = uint8(12)
	CLTypePublicKey = uint8(22)
	CLTypeOption    = uint8(13)
	CLTypeList      = uint8(14)
	CLTypeByteArray = uint8(15)
	CLTypeResult    = uint8(16)
	CLTypeMap       = uint8(17)
	CLTypeTuple1    = uint8(18)
	CLTypeTuple2    = uint8(19)
	CLTypeTuple3    = uint8(20)
	CLTypeAny       = uint8(21)
)

type ToBytes interface {
	ToBytes() []byte
}

type CLTypedAndToBytes interface {
	ToBytes
	ClType() uint8
	ClTypeToBytes() []byte
	ClTypeToJson() interface{}
}

// reverse 切片反序
func reverse(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func toBytesBytesArray(arr []byte) []byte {
	return arr
}

func toBytesArrayU8(arr []byte) []byte {
	body := make([]byte, 0)
	body = append(toBytesU32(uint64(len(arr))), arr...)
	return body
}

func toBytesVec(vec []ToBytes) []byte {
	body := make([]byte, 0)
	for _, e := range vec {
		body = append(body, e.ToBytes()...)
	}
	body = append(toBytesU32(uint64(len(vec))), body...)
	return body
}

func toBytesString(str string) []byte {
	body := []byte(str)
	body = append(toBytesU32(uint64(len(body))), body...)
	return body
}

func toBytesU32(v uint64) []byte {
	return toBytesNumber(32, false, new(big.Int).SetUint64(v))
}

func toBytesNumber(bitSize uint64, signed bool, value *big.Int) []byte {

	body := make([]byte, 0)

	if signed {
		// 暂不支持有符号的转换
		return nil
	}

	v := value.Bytes()
	if bitSize > 64 {
		body = append(v, uint8(len(v)))
		body = reverse(body)
	} else {
		body = reverse(v)
		byteLength := bitSize / 8
		i := uint64(len(v))
		for i < byteLength {
			body = append(body, 0)
			i++
		}
	}

	return body
}
