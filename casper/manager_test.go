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
	"encoding/json"
	"github.com/astaxie/beego/config"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/log"
	"github.com/blocktree/openwallet/v2/openwallet"
	"path/filepath"
	"testing"
)

var (
	tw *WalletManager
)

func init() {
	tw = testNewWalletManager()
}

func testNewWalletManager() *WalletManager {
	wm := NewWalletManager()

	//读取配置
	absFile := filepath.Join("conf", "CSPR.ini")
	c, err := config.NewConfig("ini", absFile)
	if err != nil {
		return nil
	}
	wm.LoadAssetsConfig(c)
	wm.WalletClient.Debug = true
	return wm
}

func TestWalletManager_GetStateRootHash(t *testing.T) {
	r, err := tw.GetStateRootHash()
	if err != nil {
		t.Errorf("GetStateRootHash failed, err: %v", err)
		return
	}
	log.Infof("stateRootHash: %s", r)
}

func TestWalletManager_GetLatestBlockInfo(t *testing.T) {
	r, err := tw.GetLatestBlockInfo()
	if err != nil {
		t.Errorf("GetLatestBlockInfo failed, err: %v", err)
		return
	}
	log.Infof("block: %v", r)
}

func TestWalletManager_GetBlockByHeight(t *testing.T) {
	block, err := tw.GetBlockByHeight(29541)
	if err != nil {
		t.Errorf("GetBlockByHeight failed, err: %v", err)
		return
	}
	log.Infof("block: %+v", block)
}

func TestWalletManager_GetBlockByHash(t *testing.T) {
	block, err := tw.GetBlockByHash("b1b42ef0e8938ec006a579785edd06be7ff3fe243064e631a603b66da3d2c90c")
	if err != nil {
		t.Errorf("GetBlockByHash failed, err: %v", err)
		return
	}
	log.Infof("block: %+v", block)
}

func TestWalletManager_GetPurseUref(t *testing.T) {
	pubkey := "bf5e23418fa1b95c2be8cb900308b028d001f5626d1a2732cbe9caab71ad2cc3"
	stateRootHash, err := tw.GetStateRootHash()
	if err != nil {
		t.Errorf("GetStateRootHash failed, err: %v", err)
		return
	}
	purseUref, err := tw.GetPurseUref(stateRootHash, PublicKeyToHash(pubkey, ED25519_TAG))
	if err != nil {
		t.Errorf("GetPurseUref failed, err: %v", err)
		return
	}
	purseUref, _ = tw.GetPurseUref(stateRootHash, PublicKeyToHash(pubkey, ED25519_TAG))
	log.Infof("purseUref: %v", purseUref)
}

func TestWalletManager_GetAccountBalance(t *testing.T) {
	pubkey := "96377909058287e15ae2a3df5b77dc0abcd41136bdf8f919d5ffb412777ae475"
	stateRootHash, err := tw.GetStateRootHash()
	if err != nil {
		t.Errorf("GetStateRootHash failed, err: %v", err)
		return
	}
	r, err := tw.GetAccountBalance(stateRootHash, PublicKeyToHash(pubkey, ED25519_TAG))
	if err != nil {
		t.Errorf("GetAccountBalance failed, err: %v", err)
		return
	}
	log.Infof("account balance: %v", r)
}

func TestWalletManager_GetAccountBalanceByHash(t *testing.T) {
	hash := "8543cf28d54200d36842679074575ef714d5562341b8a59f0d63ad4465c11365"
	stateRootHash, err := tw.GetStateRootHash()
	if err != nil {
		t.Errorf("GetStateRootHash failed, err: %v", err)
		return
	}
	r, err := tw.GetAccountBalance(stateRootHash, hash)
	if err != nil {
		t.Errorf("GetAccountBalance failed, err: %v", err)
		return
	}
	log.Infof("account balance: %v", r)
}

func TestPublicKeyToHash(t *testing.T) {
	pubkey := "96377909058287e15ae2a3df5b77dc0abcd41136bdf8f919d5ffb412777ae475"
	hash := PublicKeyToHash(pubkey, ED25519_TAG)
	if len(hash) == 0 {
		t.Errorf("PublicKeyToHash failed")
		return
	}
	log.Infof("hash: %s", hash)
}

func TestWalletManager_GetBlockTransfers(t *testing.T) {
	transfers, err := tw.GetBlockTransfers(29541)
	if err != nil {
		t.Errorf("GetBlockTransfers failed, err: %v", err)
		return
	}
	for i, tx := range transfers {
		log.Infof("tx[%d]: %+v", i, tx)
	}

}

func TestWalletManager_TransferDeploy(t *testing.T) {

	privateKey, _ := hex.DecodeString("")
	senderKey := "96377909058287e15ae2a3df5b77dc0abcd41136bdf8f919d5ffb412777ae475"
	//recipientKey := PublicKeyToHash("8543cf28d54200d36842679074575ef714d5562341b8a59f0d63ad4465c11365", ED25519_TAG)
	recipientKey := "8543cf28d54200d36842679074575ef714d5562341b8a59f0d63ad4465c11365"
	paymentAmount := "10000"
	transferAmount := "87000000000"
	id := "1"

	deploy, err := tw.MakeTransferDeploy(senderKey, recipientKey, transferAmount, paymentAmount, id, 0)
	if err != nil {
		t.Errorf("MakeTransferDeploy failed, err: %v", err)
		return
	}

	//serializedHeader := serializeHeader(deploy.Header)
	//log.Infof("serializedHeader Bytes: %s", hex.EncodeToString(serializedHeader))

	//deploy.hash:  499f43c30bde666764ffa503fba2630cef582cd124cbb3c96770dab07b5bf2da
	//deploy.header.bodyHash:  cc7217baa2df07b0dd1e99331a79e19290ddbb5eed8f513fec8c787a64b8e4ee

	log.Infof("deploy.hash: %s", deploy.Hash)
	log.Infof("deploy.header.bodyHash: %s", hex.EncodeToString(deploy.Header.BodyHash))

	msg, _ := hex.DecodeString(deploy.Hash)
	sig, _, ret := owcrypt.Signature(privateKey, nil, msg, owcrypt.ECC_CURVE_ED25519_NORMAL)
	if ret != owcrypt.SUCCESS {
		t.Errorf("owcrypt.Signature failed, err: %v", ret)
	}

	signature := &openwallet.KeySignature{
		EccType:   owcrypt.ECC_CURVE_ED25519,
		Address:   &openwallet.Address{
			Address:     PublicKeyToHash(senderKey, ED25519_TAG),
			PublicKey:   senderKey,
		},
		Signature: hex.EncodeToString(sig),
	}

	tw.AddSignatureToDeploy(deploy, signature)

	js, err := json.Marshal(deploy)
	if err != nil {
		t.Errorf("deploy to json failed, err: %v", err)
		return
	}
	log.Infof("%s", js)

	txid, err := tw.PutDeploy(deploy)
	if err != nil {
		t.Errorf("PutDeploy failed, err: %v", err)
		return
	}
	log.Infof("txid: %s", txid)
}

func TestWalletManager_GetDeployInfo(t *testing.T) {
	_, err := tw.GetDeployInfo("78188bc788837cb1aa38689cd0271086bb9a99971380a0bf46382b863c33e133")
	if err != nil {
		t.Errorf("GetDeployInfo failed, err: %v", err)
		return
	}
}
