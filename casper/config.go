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
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/common/file"
	"github.com/shopspring/decimal"
	"path/filepath"
	"strings"
)

const (
	//币种
	Symbol    = "CSPR"
	CurveType = owcrypt.ECC_CURVE_ED25519
	Decimals  = int32(9)
)

type WalletConfig struct {

	//币种
	Symbol string
	//本地数据库文件路径
	DBPath string
	//钱包服务API
	ServerAPI string
	//最低手续费
	MinFees decimal.Decimal
	//最新转账金额
	TransferMinimumMotes decimal.Decimal
	//数据目录
	DataDir string
	//曲线类型
	CurveType uint32
	//网络名
	NetworkName string
}

func NewConfig(symbol string) *WalletConfig {

	c := WalletConfig{}

	//币种
	c.Symbol = symbol
	c.CurveType = CurveType
	//本地数据库文件路径
	c.DBPath = filepath.Join("data", strings.ToLower(c.Symbol), "db")
	//最低手续费
	c.MinFees = decimal.Zero

	return &c
}

//创建文件夹
func (wc *WalletConfig) makeDataDir() {

	if len(wc.DataDir) == 0 {
		//默认路径当前文件夹./data
		wc.DataDir = "data"
	}

	//本地数据库文件路径
	wc.DBPath = filepath.Join(wc.DataDir, strings.ToLower(wc.Symbol), "db")

	//创建目录
	file.MkdirAll(wc.DBPath)
}
