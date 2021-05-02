/*
 * Copyright 2018 The openwallet Authors
 * This file is part of the openwallet library.
 *
 * The openwallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The openwallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

package casper

import (
	"encoding/hex"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/log"
	"github.com/blocktree/openwallet/v2/openwallet"
	"github.com/shopspring/decimal"
	"github.com/tidwall/gjson"
	"strings"
	"time"
)

type WalletManager struct {
	openwallet.AssetsAdapterBase
	WalletClient    *Client                         // 节点客户端
	Config          *WalletConfig                   //钱包管理配置
	Decoder         openwallet.AddressDecoder       //地址编码器
	DecoderV2       openwallet.AddressDecoderV2     //地址编码器
	TxDecoder       openwallet.TransactionDecoder   //交易单编码器
	Log             *log.OWLogger                   //日志工具
	Blockscanner    openwallet.BlockScanner         //区块扫描器
	ContractDecoder openwallet.SmartContractDecoder //智能合约解析器
	balanceUrefs    map[string]string               //hash => purseUref 缓存
}

func NewWalletManager() *WalletManager {
	wm := WalletManager{}
	wm.Config = NewConfig(Symbol)
	//wm.Decoder = NewAddressDecoder(&wm)
	wm.DecoderV2 = &AddressDecoderV2{}
	wm.Log = log.NewOWLogger(wm.Symbol())
	wm.Blockscanner = NewBlockScanner(&wm)
	wm.TxDecoder = NewTransactionDecoder(&wm)

	wm.balanceUrefs = make(map[string]string)
	return &wm
}

func (wm *WalletManager) GetStateRootHash() (string, error) {

	result, err := wm.WalletClient.Call("chain_get_state_root_hash", nil)
	if err != nil {
		return "", err
	}
	stateRootHash := result.Get("state_root_hash").String()
	return stateRootHash, nil
}

func (wm *WalletManager) GetBlockInfo(value interface{}, identifier uint8) (*Block, error) {
	var params interface{}
	switch identifier {
	case BlockIdentifierLastBlock:
		params = nil
	case BlockIdentifierHeight:
		params = map[string]interface{}{
			"block_identifier": map[string]interface{}{
				"Height": value,
			}}
	case BlockIdentifierHash:
		params = map[string]interface{}{
			"block_identifier": map[string]interface{}{
				"Hash": value,
			}}
	}

	result, err := wm.WalletClient.Call("chain_get_block", params)
	if err != nil {
		return nil, err
	}
	block := NewBlock(result.Get("block"))
	return block, nil
}

func (wm *WalletManager) GetLatestBlockInfo() (*Block, error) {
	return wm.GetBlockInfo(nil, BlockIdentifierLastBlock)
}

func (wm *WalletManager) GetBlockByHeight(height uint64) (*Block, error) {
	return wm.GetBlockInfo(height, BlockIdentifierHeight)
}

func (wm *WalletManager) GetBlockByHash(hash string) (*Block, error) {
	return wm.GetBlockInfo(hash, BlockIdentifierHash)
}

func (wm *WalletManager) GetPurseUref(stateRootHash, hash string) (string, error) {

	purse := wm.balanceUrefs[hash]

	params := map[string]string{
		"state_root_hash": stateRootHash,
		"key":             "account-hash-" + hash,
	}
	result, err := wm.WalletClient.Call("state_get_item", params)
	if err != nil {
		return "", err
	}
	purse = result.Get("stored_value.Account.main_purse").String()
	wm.balanceUrefs[hash] = purse
	return purse, nil
}

func (wm *WalletManager) GetAccountBalance(stateRootHash, hash string) (decimal.Decimal, error) {
	purse, err := wm.GetPurseUref(stateRootHash, hash)
	if err != nil {
		return decimal.Zero, err
	}
	params := map[string]string{
		"state_root_hash": stateRootHash,
		"purse_uref":      purse,
	}
	result, err := wm.WalletClient.Call("state_get_balance", params)
	if err != nil {
		return decimal.Zero, err
	}
	balance, _ := decimal.NewFromString(result.Get("balance_value").String())
	balance = balance.Shift(-wm.Decimal())
	return balance, nil
}

func ToAccountHex(publicKey string) string {
	bytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return ""
	}
	acc := append([]byte{ED25519_TAG}, bytes...)
	accountHex := hex.EncodeToString(acc)
	return accountHex
}

// PublicKeyToHash 公钥转hash hex
func PublicKeyToHash(publicKey string, tag uint8) string {
	bytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return ""
	}
	if len(bytes) < 32 {
		return ""
	}
	hash := make([]byte, 0)
	switch tag {
	case 1:
		hash = append([]byte(SignatureAlgorithmEd25519), 0x00)
	case 2:
		hash = append([]byte(SignatureAlgorithmSecp256K1), 0x00)
	}
	hash = append(hash, bytes...)
	b2 := owcrypt.Hash(hash, 32, owcrypt.HASH_ALG_BLAKE2B)
	return hex.EncodeToString(b2)
}

func (wm *WalletManager) AddressToHash(address string) string {
	bytes, err := hex.DecodeString(address)
	if err != nil {
		return ""
	}
	if len(bytes) < 33 {
		return ""
	}
	tag := bytes[0]
	hash := make([]byte, 0)
	switch tag {
	case 0x01:
		hash = append([]byte(SignatureAlgorithmEd25519), 0x00)
	case 0x02:
		hash = append([]byte(SignatureAlgorithmSecp256K1), 0x00)
	}
	hash = append(hash, bytes[1:]...)
	b2 := owcrypt.Hash(hash, 32, owcrypt.HASH_ALG_BLAKE2B)
	return hex.EncodeToString(b2)
}

func (wm *WalletManager) GetBlockTransfers(height uint64) ([]*Transfer, error) {
	params := map[string]interface{}{
		"block_identifier": map[string]interface{}{
			"Height": height,
		}}

	result, err := wm.WalletClient.Call("chain_get_block_transfers", params)
	if err != nil {
		return nil, err
	}
	blockHash := result.Get("block_hash").String()
	transfers := make([]*Transfer, 0)
	if result.Get("transfers").IsArray() {
		for _, t := range result.Get("transfers").Array() {
			tx := &Transfer{
				Amount:      t.Get("amount").String(),
				Target:      t.Get("target").String(),
				ID:          t.Get("id").String(),
				From:        t.Get("from").String(),
				To:          t.Get("to").String(),
				DeployHash:  t.Get("deploy_hash").String(),
				Source:      t.Get("source").String(),
				Gas:         t.Get("gas").String(),
				BlockHeight: height,
				BlockHash:   blockHash,
			}
			tx.From = strings.TrimPrefix(tx.From, "account-hash-")
			tx.To = strings.TrimPrefix(tx.To, "account-hash-")
			amount_dec, _ := decimal.NewFromString(tx.Amount)
			amount := amount_dec.Shift(-wm.Decimal())
			tx.Amount = amount.String()
			transfers = append(transfers, tx)
		}
	}

	return transfers, nil
}

func (wm *WalletManager) MakeTransferDeploy(sender, to, amount, fee, id string, timestamp int64) (*Deploy, error) {

	target, err := hex.DecodeString(to)
	if err != nil {
		return nil, err
	}

	account, err := hex.DecodeString(sender)
	if err != nil {
		return nil, err
	}

	session := NewTransfer(amount, target, id)
	payment := StandardPayment(fee)

	serializedBody := serializeBody(payment, session)
	bodyHash := owcrypt.Hash(serializedBody, 32, owcrypt.HASH_ALG_BLAKE2B)

	header := &Header{
		Account: &PublicKey{
			RawPublicKey: account,
			Tag:          ED25519_TAG,
		},
		ChainName: wm.Config.NetworkName,
		GasPrice:  1,
		//Timestamp: time.Now().UTC(),
		Ttl:          1800000,
		BodyHash:     bodyHash,
		Dependencies: make([]ToBytes, 0),
	}

	if timestamp == 0 {
		header.Timestamp = time.Now().Unix()
	} else {
		header.Timestamp = timestamp
	}

	serializedHeader := serializeHeader(header)
	deployHash := owcrypt.Hash(serializedHeader, 32, owcrypt.HASH_ALG_BLAKE2B)

	deploy := &Deploy{
		Hash:      hex.EncodeToString(deployHash),
		Header:    header,
		Payment:   payment,
		Transfer:  session,
		Approvals: make([]*Approval, 0),
	}

	return deploy, nil
}

func (wm *WalletManager) AddSignatureToDeploy(deploy *Deploy, keySig *openwallet.KeySignature) {

	signature := ""
	switch keySig.EccType {
	case owcrypt.ECC_CURVE_ED25519:
		signature = "01" + keySig.Signature
		break
	case owcrypt.ECC_CURVE_SECP256K1:
		signature = "02" + keySig.Signature
		break
	}

	approval := &Approval{
		Signature: signature,
		Signer:    ToAccountHex(keySig.Address.PublicKey),
	}

	if deploy.Approvals == nil {
		deploy.Approvals = make([]*Approval, 0)
	}

	deploy.Approvals = append(deploy.Approvals, approval)
}

func (wm *WalletManager) PutDeploy(deploy *Deploy) (string, error) {
	params := map[string]interface{}{
		"deploy": deploy,
	}
	result, err := wm.WalletClient.Call("account_put_deploy", params)
	if err != nil {
		return "", err
	}
	txid := result.Get("deploy_hash").String()
	return txid, nil
}

func (wm *WalletManager) GetDeployInfo(txid string) (*gjson.Result, error) {
	params := map[string]interface{}{
		"deploy_hash": txid,
	}
	result, err := wm.WalletClient.Call("info_get_deploy", params)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (wm *WalletManager) AddSignatureToDeployParam(deploy map[string]interface{}, keySig *openwallet.KeySignature) map[string]interface{} {

	signature := ""
	switch keySig.EccType {
	case owcrypt.ECC_CURVE_ED25519:
		signature = "01" + keySig.Signature
		break
	case owcrypt.ECC_CURVE_SECP256K1:
		signature = "02" + keySig.Signature
		break
	}

	approval := &Approval{
		Signature: signature,
		Signer:    ToAccountHex(keySig.Address.PublicKey),
	}

	approvals := make([]*Approval, 0)
	approvals = append(approvals, approval)
	deploy["approvals"] = approvals

	return deploy
}

func (wm *WalletManager) PutDeployParam(deploy map[string]interface{}) (string, error) {
	params := map[string]interface{}{
		"deploy": deploy,
	}
	result, err := wm.WalletClient.Call("account_put_deploy", params)
	if err != nil {
		return "", err
	}
	txid := result.Get("deploy_hash").String()
	return txid, nil
}
