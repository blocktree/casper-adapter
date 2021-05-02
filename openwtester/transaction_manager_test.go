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

package openwtester

import (
	"github.com/astaxie/beego/config"
	"github.com/blocktree/openwallet/v2/openw"
	"path/filepath"
	"testing"

	"github.com/blocktree/openwallet/v2/log"
	"github.com/blocktree/openwallet/v2/openwallet"
)

func TestWalletManager_GetAssetsAccountBalance(t *testing.T) {
	tm := testInitWalletManager()
	walletID := "W86nWchZDQ5e8KtzfWTSQPqaVysu68kLhN"
	accountID := "5bjerWYdMiSP8t6guHhu96X9XFCP8S6hDQJRCnJbzEh7"
	//accountID := "GYtwYMnxxAPhuAasvpRmy8DrJcdipAn84w1NvyYBtK1N"
	balance, err := tm.GetAssetsAccountBalance(testApp, walletID, accountID)
	if err != nil {
		log.Error("GetAssetsAccountBalance failed, unexpected error:", err)
		return
	}
	log.Info("balance:", balance)
}

func TestWalletManager_GetEstimateFeeRate(t *testing.T) {
	tm := testInitWalletManager()
	coin := openwallet.Coin{
		Symbol: "CSPR",
	}
	feeRate, unit, err := tm.GetEstimateFeeRate(coin)
	if err != nil {
		log.Error("GetEstimateFeeRate failed, unexpected error:", err)
		return
	}
	log.Std.Info("feeRate: %s %s/%s", feeRate, coin.Symbol, unit)
}

func TestGetAddressVerify(t *testing.T) {
	symbol := "CSPR"
	assetsMgr, err := openw.GetAssetsAdapter(symbol)
	if err != nil {
		log.Error(symbol, "is not support")
		return
	}
	//读取配置
	absFile := filepath.Join(configFilePath, symbol+".ini")

	c, err := config.NewConfig("ini", absFile)
	if err != nil {
		return
	}
	assetsMgr.LoadAssetsConfig(c)
	addrDec := assetsMgr.GetAddressDecoderV2()

	flag := addrDec.AddressVerify("0x4402a2969da0689a0e6f5fbad8be930430b4ad63af25f3c93dbd03bb40908d08")
	log.Infof("flag: %v, expect: false", flag)

	flag = addrDec.AddressVerify("96377909058287e15ae2a3df5b77dc0abcd41136bdf8f919d5ffb412777ae475")
	log.Infof("flag: %v, expect: false", flag)

	flag = addrDec.AddressVerify("0196377909058287e15ae2a3df5b77dc0abcd41136bdf8f919d5ffb412777ae475")
	log.Infof("flag: %v, expect: true", flag)

}
