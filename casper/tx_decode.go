/*
 * Copyright 2019 The openwallet Authors
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
	"fmt"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/openwallet"
	"github.com/shopspring/decimal"
	"time"
)

type TransactionDecoder struct {
	openwallet.TransactionDecoderBase
	wm *WalletManager //钱包管理者
}

//NewTransactionDecoder 交易单解析器
func NewTransactionDecoder(wm *WalletManager) *TransactionDecoder {
	decoder := TransactionDecoder{}
	decoder.wm = wm
	return &decoder
}

//CreateRawTransaction 创建交易单
func (decoder *TransactionDecoder) CreateRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {

	var (
		accountID       = rawTx.Account.AccountID
		findAddrBalance *openwallet.Address
	)

	//获取wallet
	addresses, err := wrapper.GetAddressList(0, -1, "AccountID", accountID) //wrapper.GetWallet().GetAddressesByAccount(rawTx.Account.AccountID)
	if err != nil {
		return err
	}

	if len(addresses) == 0 {
		return openwallet.Errorf(openwallet.ErrAccountNotAddress, "[%s] have not addresses", accountID)
	}

	var amountStr string
	for _, v := range rawTx.To {
		amountStr = v
		break
	}

	amount, _ := decimal.NewFromString(amountStr)

	//检查转账金额是否超过最低成本
	if amount.LessThan(decoder.wm.Config.TransferMinimumMotes) {
		return fmt.Errorf("The transfer amount is lower than the minimum transfer amount. ")
	}

	stateRootHash, err := decoder.wm.GetStateRootHash()
	if err != nil {
		return err
	}

	for _, addr := range addresses {

		balance, err := decoder.wm.GetAccountBalance(stateRootHash, addr.Address)
		if err != nil {
			continue
		}

		//余额不足查找下一个地址
		totalSend := amount.Add(decoder.wm.Config.MinFees)
		if balance.GreaterThanOrEqual(totalSend) {
			//只要找到一个合适使用的地址余额就停止遍历
			findAddrBalance = addr
			break
		}
	}

	if findAddrBalance == nil {
		return openwallet.Errorf(openwallet.ErrInsufficientBalanceOfAccount, "all address's balance of account is not enough")
	}

	//最后创建交易单
	err = decoder.createRawTransaction(
		wrapper,
		rawTx,
		findAddrBalance)
	if err != nil {
		return err
	}

	return nil

}

//SignRawTransaction 签名交易单
func (decoder *TransactionDecoder) SignRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {

	if rawTx.Signatures == nil || len(rawTx.Signatures) == 0 {
		//this.wm.Log.Std.Error("len of signatures error. ")
		return fmt.Errorf("transaction signature is empty")
	}

	key, err := wrapper.HDKey()
	if err != nil {
		return err
	}

	keySignatures := rawTx.Signatures[rawTx.Account.AccountID]
	if keySignatures != nil {
		for _, keySignature := range keySignatures {

			childKey, err := key.DerivedKeyWithPath(keySignature.Address.HDPath, keySignature.EccType)
			keyBytes, err := childKey.GetPrivateKeyBytes()
			if err != nil {
				return err
			}

			//publicKey, _ := hex.DecodeString(keySignature.Address.PublicKey)

			msg, err := hex.DecodeString(keySignature.Message)
			if err != nil {
				return fmt.Errorf("decoder transaction hash failed, unexpected err: %v", err)
			}

			//msg := append([]byte(decoder.wm.Config.NetworkID), hash...)
			sig, _, ret := owcrypt.Signature(keyBytes, nil, msg, keySignature.EccType)
			if ret != owcrypt.SUCCESS {
				return fmt.Errorf("sign transaction hash failed, unexpected err: %v", err)
			}

			decoder.wm.Log.Debugf("message: %s", hex.EncodeToString(msg))
			//decoder.wm.Log.Debugf("publicKey: %s", hex.EncodeToString(publicKey))
			//decoder.wm.Log.Debugf("privateKey : %s", hex.EncodeToString(keyBytes))
			//decoder.wm.Log.Debugf("signature: %s", hex.EncodeToString(sig))

			keySignature.Signature = hex.EncodeToString(sig)
		}
	}

	decoder.wm.Log.Info("transaction hash sign success")

	rawTx.Signatures[rawTx.Account.AccountID] = keySignatures

	return nil
}

//VerifyRawTransaction 验证交易单，验证交易单并返回加入签名后的交易单
func (decoder *TransactionDecoder) VerifyRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {

	if rawTx.Signatures == nil || len(rawTx.Signatures) == 0 {
		//this.wm.Log.Std.Error("len of signatures error. ")
		return fmt.Errorf("transaction signature is empty")
	}

	var deploy map[string]interface{}
	err := json.Unmarshal([]byte(rawTx.RawHex), &deploy)
	if err != nil {
		return err
	}

	//支持多重签名
	for accountID, keySignatures := range rawTx.Signatures {
		decoder.wm.Log.Debug("accountID Signatures:", accountID)
		for _, keySignature := range keySignatures {

			messsage, _ := hex.DecodeString(keySignature.Message)
			signature, _ := hex.DecodeString(keySignature.Signature)
			publicKey, _ := hex.DecodeString(keySignature.Address.PublicKey)

			//decoder.wm.Log.Debug("txHex:", hex.EncodeToString(txHex))
			//decoder.wm.Log.Debug("Signature:", keySignature.Signature)
			//验证签名
			ret := owcrypt.Verify(publicKey, nil, messsage, signature, keySignature.EccType)
			if ret != owcrypt.SUCCESS {
				return fmt.Errorf("transaction verify failed")
			}

			deploySigned := decoder.wm.AddSignatureToDeployParam(deploy, keySignature)

			txJson, _ := json.Marshal(deploySigned)
			rawTx.RawHex = string(txJson)
			rawTx.IsCompleted = true

		}
	}

	return nil
}

//SendRawTransaction 广播交易单
func (decoder *TransactionDecoder) SubmitRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) (*openwallet.Transaction, error) {

	var deploySigned map[string]interface{}
	err := json.Unmarshal([]byte(rawTx.RawHex), &deploySigned)
	if err != nil {
		return nil, err
	}

	txid, err := decoder.wm.PutDeployParam(deploySigned)
	if err != nil {
		return nil, err
	}

	decoder.wm.Log.Infof("Transaction [%s] submitted to the network successfully.", txid)

	rawTx.TxID = txid
	rawTx.IsSubmit = true

	decimals := decoder.wm.Decimal()

	//记录一个交易单
	tx := &openwallet.Transaction{
		From:       rawTx.TxFrom,
		To:         rawTx.TxTo,
		Amount:     rawTx.TxAmount,
		Coin:       rawTx.Coin,
		TxID:       rawTx.TxID,
		Decimal:    decimals,
		AccountID:  rawTx.Account.AccountID,
		Fees:       rawTx.Fees,
		SubmitTime: time.Now().Unix(),
	}

	tx.WxID = openwallet.GenTransactionWxID(tx)

	return tx, nil
}

//GetRawTransactionFeeRate 获取交易单的费率
func (decoder *TransactionDecoder) GetRawTransactionFeeRate() (feeRate string, unit string, err error) {
	return decoder.wm.Config.MinFees.String(), "TX", nil
}

//CreateSummaryRawTransaction 创建汇总交易
func (decoder *TransactionDecoder) CreateSummaryRawTransaction(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransaction, error) {

	var (
		rawTxArray         = make([]*openwallet.RawTransaction, 0)
		accountID          = sumRawTx.Account.AccountID
		minTransfer, _     = decimal.NewFromString(sumRawTx.MinTransfer)
		retainedBalance, _ = decimal.NewFromString(sumRawTx.RetainedBalance)
	)

	if minTransfer.Cmp(retainedBalance) < 0 {
		return nil, fmt.Errorf("mini transfer amount must be greater than address retained balance")
	}

	//获取wallet
	addresses, err := wrapper.GetAddressList(sumRawTx.AddressStartIndex, sumRawTx.AddressLimit,
		"AccountID", sumRawTx.Account.AccountID)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("[%s] have not addresses", accountID)
	}

	stateRootHash, err := decoder.wm.GetStateRootHash()
	if err != nil {
		return nil, err
	}

	for _, addr := range addresses {

		balance, err := decoder.wm.GetAccountBalance(stateRootHash, addr.Address)
		if err != nil {
			continue
		}

		if balance.LessThan(minTransfer) || balance.LessThanOrEqual(decimal.Zero) {
			continue
		}
		//计算汇总数量 = 余额 - 保留余额
		sumAmount := balance.Sub(retainedBalance)

		//减去手续费
		sumAmount = sumAmount.Sub(decoder.wm.Config.MinFees)
		if sumAmount.LessThanOrEqual(decimal.Zero) {
			continue
		}

		decoder.wm.Log.Debugf("balance: %v", balance)
		decoder.wm.Log.Debugf("fees: %v", decoder.wm.Config.MinFees.String())
		decoder.wm.Log.Debugf("sumAmount: %v", sumAmount.String())

		//检查转账金额是否超过最低成本
		if sumAmount.LessThan(decoder.wm.Config.TransferMinimumMotes) {
			continue
		}

		//创建一笔交易单
		rawTx := &openwallet.RawTransaction{
			Coin:    sumRawTx.Coin,
			Account: sumRawTx.Account,
			To: map[string]string{
				sumRawTx.SummaryAddress: sumAmount.String(),
			},
			Required: 1,
		}

		createErr := decoder.createRawTransaction(
			wrapper,
			rawTx,
			addr)
		if createErr != nil {
			return nil, createErr
		}

		//创建成功，添加到队列
		rawTxArray = append(rawTxArray, rawTx)

	}

	return rawTxArray, nil

}

//createRawTransaction
func (decoder *TransactionDecoder) createRawTransaction(
	wrapper openwallet.WalletDAI,
	rawTx *openwallet.RawTransaction,
	addrBalance *openwallet.Address) error {

	var (
		accountTotalSent = decimal.Zero
		txFrom           = make([]string, 0)
		txTo             = make([]string, 0)
		keySignList      = make([]*openwallet.KeySignature, 0)
		amountStr        string
		destination      string
	)

	decimals := decoder.wm.Decimal()

	for k, v := range rawTx.To {
		destination = k
		amountStr = v
		break
	}

	//计算账户的实际转账amount
	accountTotalSentAddresses, findErr := wrapper.GetAddressList(0, -1, "AccountID", rawTx.Account.AccountID, "Address", destination)
	if findErr != nil || len(accountTotalSentAddresses) == 0 {
		amountDec, _ := decimal.NewFromString(amountStr)
		accountTotalSent = accountTotalSent.Add(amountDec)
	}

	txFrom = []string{fmt.Sprintf("%s:%s", addrBalance.Address, amountStr)}
	txTo = []string{fmt.Sprintf("%s:%s", destination, amountStr)}

	fee := decoder.wm.Config.MinFees.Shift(decimals)
	sendAmount, _ := decimal.NewFromString(amountStr)
	sendAmount = sendAmount.Shift(decimals)
	tx, err := decoder.wm.MakeTransferDeploy(addrBalance.PublicKey, destination, sendAmount.String(), fee.String(), "1", 0)
	if err != nil {
		return err
	}

	txJson, _ := json.Marshal(tx)
	rawTx.RawHex = string(txJson)

	if rawTx.Signatures == nil {
		rawTx.Signatures = make(map[string][]*openwallet.KeySignature)
	}

	signature := openwallet.KeySignature{
		EccType: decoder.wm.Config.CurveType,
		Address: addrBalance,
		Message: tx.Hash,
	}
	keySignList = append(keySignList, &signature)

	accountTotalSent = decimal.Zero.Sub(accountTotalSent)

	//rawTx.RawHex = rawHex
	rawTx.Signatures[rawTx.Account.AccountID] = keySignList
	rawTx.FeeRate = ""
	rawTx.Fees = decoder.wm.Config.MinFees.String()
	rawTx.IsBuilt = true
	rawTx.TxAmount = accountTotalSent.StringFixed(decimals)
	rawTx.TxFrom = txFrom
	rawTx.TxTo = txTo

	return nil
}

//CreateSummaryRawTransactionWithError 创建汇总交易，返回能原始交易单数组（包含带错误的原始交易单）
func (decoder *TransactionDecoder) CreateSummaryRawTransactionWithError(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransactionWithError, error) {
	raTxWithErr := make([]*openwallet.RawTransactionWithError, 0)
	rawTxs, err := decoder.CreateSummaryRawTransaction(wrapper, sumRawTx)
	if err != nil {
		return nil, err
	}
	for _, tx := range rawTxs {
		raTxWithErr = append(raTxWithErr, &openwallet.RawTransactionWithError{
			RawTx: tx,
			Error: nil,
		})
	}
	return raTxWithErr, nil
}
