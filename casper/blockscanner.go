/*
 * Copyright 2018 The OpenWallet Authors
 * This file is part of the OpenWallet library.
 *
 * The OpenWallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The OpenWallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

package casper

import (
	"fmt"
	"github.com/blocktree/openwallet/v2/log"
	"github.com/blocktree/openwallet/v2/openwallet"
	"time"
)

const (
	maxExtractingSize = 10 // thread count
)

//BlockScanner block scanner
type BlockScanner struct {
	*openwallet.BlockScannerBase

	CurrentBlockHeight   uint64         //当前区块高度
	extractingCH         chan struct{}  //扫描工作令牌
	wm                   *WalletManager //钱包管理者
	RescanLastBlockCount uint64         //重扫上N个区块数量
}

//ExtractResult extract result
type ExtractResult struct {
	extractData map[string]*openwallet.TxExtractData
	TxID        string
	BlockHash   string
	BlockHeight uint64
	BlockTime   int64
	Success     bool
}

//SaveResult result
type SaveResult struct {
	TxID        string
	BlockHeight uint64
	Success     bool
}

// NewBlockScanner create a block scanner
func NewBlockScanner(wm *WalletManager) *BlockScanner {
	bs := BlockScanner{
		BlockScannerBase: openwallet.NewBlockScannerBase(),
	}

	bs.extractingCH = make(chan struct{}, maxExtractingSize)
	bs.wm = wm
	bs.RescanLastBlockCount = 0

	// set task
	bs.SetTask(bs.ScanBlockTask)

	return &bs
}

// ScanBlockTask scan block task
func (bs *BlockScanner) ScanBlockTask() {

	var (
		currentHeight uint64
		currentHash   string
	)

	// get local block header
	currentHeight, currentHash, err := bs.GetLocalBlockHead()

	if err != nil {
		bs.wm.Log.Std.Error("", err)
	}

	if currentHeight == 0 {
		bs.wm.Log.Std.Info("No records found in local, get current block as the local!")

		headBlock, err := bs.wm.GetLatestBlockInfo()
		if err != nil {
			bs.wm.Log.Std.Info("get head block error, err=%v", err)
		}

		currentHash = headBlock.Previousblockhash
		currentHeight = headBlock.Height - 1
	}

	for {
		if !bs.Scanning {
			// stop scan
			return
		}

		lastBlock, err := bs.wm.GetLatestBlockInfo()
		if err != nil {
			bs.wm.Log.Errorf("block scanner GetLatestBlock failed, err: %v", err)
			break
		}

		maxBlockHeight := lastBlock.Height

		bs.wm.Log.Info("current block height:", currentHeight, " maxBlockHeight:", maxBlockHeight)
		if uint64(currentHeight) >= maxBlockHeight {
			bs.wm.Log.Std.Info("block scanner has scanned full chain data. Current height %d", maxBlockHeight)
			break
		}

		// next block
		currentHeight = currentHeight + 1

		bs.wm.Log.Std.Info("block scanner scanning height: %d ...", currentHeight)
		block, err := bs.wm.GetBlockByHeight(currentHeight)

		if err != nil {
			bs.wm.Log.Std.Info("block scanner can not get new block data by rpc; unexpected error: %v", err)
			break
		}

		if currentHash != block.Previousblockhash {
			bs.wm.Log.Std.Info("block has been fork on height: %d.", currentHeight)
			bs.wm.Log.Std.Info("block height: %d local hash = %s ", currentHeight-1, currentHash)
			bs.wm.Log.Std.Info("block height: %d mainnet hash = %s ", currentHeight-1, block.Previousblockhash)
			bs.wm.Log.Std.Info("delete recharge records on block height: %d.", currentHeight-1)

			// get local fork bolck
			forkBlock, _ := bs.GetLocalBlock(currentHeight - 1)
			// delete last unscan block
			bs.DeleteUnscanRecord(currentHeight - 1)
			currentHeight = currentHeight - 2 // scan back to last 2 block
			if currentHeight <= 0 {
				currentHeight = 1
			}
			localBlock, err := bs.GetLocalBlock(currentHeight)
			if err != nil {
				bs.wm.Log.Std.Error("block scanner can not get local block; unexpected error: %v", err)
				//get block from rpc
				bs.wm.Log.Info("block scanner prev block height:", currentHeight)
				curBlock, err := bs.wm.GetBlockByHeight(currentHeight)
				if err != nil {
					bs.wm.Log.Std.Error("block scanner can not get prev block by rpc; unexpected error: %v", err)
					break
				}
				currentHash = curBlock.Hash
			} else {
				//重置当前区块的hash
				currentHash = localBlock.Hash
			}
			bs.wm.Log.Std.Info("rescan block on height: %d, hash: %s .", currentHeight, currentHash)

			//重新记录一个新扫描起点
			bs.SaveLocalBlockHead(currentHeight, currentHash)

			if forkBlock != nil {
				//通知分叉区块给观测者，异步处理
				bs.forkBlockNotify(forkBlock)
			}

		} else {
			currentHash = block.Hash
			err := bs.BatchExtractTransactions(currentHeight, currentHash, int64(block.Time))
			if err != nil {
				bs.wm.Log.Std.Error("block scanner ran BatchExtractTransactions occured unexpected error: %v", err)
			}

			//保存本地新高度
			bs.SaveLocalBlockHead(currentHeight, currentHash)
			bs.SaveLocalBlock(block)
			//通知新区块给观测者，异步处理
			bs.newBlockNotify(block)
		}
	}

	//重扫前N个块，为保证记录找到
	//for i := currentHeight - bs.RescanLastBlockCount; i <= currentHeight; i++ {
	//	bs.scanBlock(i)
	//}

	//重扫失败区块
	bs.RescanFailedRecord()

}

//newBlockNotify 获得新区块后，通知给观测者
func (bs *BlockScanner) forkBlockNotify(block *Block) {
	header := block.BlockHeader(bs.wm.Symbol())
	header.Fork = true
	bs.NewBlockNotify(header)
}

//newBlockNotify 获得新区块后，通知给观测者
func (bs *BlockScanner) newBlockNotify(block *Block) {
	header := block.BlockHeader(bs.wm.Symbol())
	bs.NewBlockNotify(header)
}

// BatchExtractTransactions 批量提取交易单
func (bs *BlockScanner) BatchExtractTransactions(blockHeight uint64, blockHash string, blockTime int64) error {

	//查询区块中的转账交易单
	transfers, err := bs.wm.GetBlockTransfers(blockHeight)
	if err != nil {
		return err
	}

	var (
		quit       = make(chan struct{})
		done       = 0 //完成标记
		failed     = 0
		shouldDone = len(transfers) //需要完成的总数
	)

	if len(transfers) == 0 {
		return nil
	}

	bs.wm.Log.Std.Info("block scanner ready extract transactions total: %d ", len(transfers))

	//生产通道
	producer := make(chan ExtractResult)
	defer close(producer)

	//消费通道
	worker := make(chan ExtractResult)
	defer close(worker)

	//保存工作
	saveWork := func(height uint64, result chan ExtractResult) {
		//回收创建的地址
		for gets := range result {

			if gets.Success {
				notifyErr := bs.newExtractDataNotify(height, gets.extractData)
				if notifyErr != nil {
					failed++ //标记保存失败数
					bs.wm.Log.Std.Info("newExtractDataNotify unexpected error: %v", notifyErr)
				}
			} else {
				//记录未扫区块
				unscanRecord := openwallet.NewUnscanRecord(height, "", "", bs.wm.Symbol())
				bs.SaveUnscanRecord(unscanRecord)
				failed++ //标记保存失败数
			}
			//累计完成的线程数
			done++
			if done == shouldDone {
				close(quit) //关闭通道，等于给通道传入nil
			}
		}
	}

	//提取工作
	extractWork := func(mtxs []*Transfer, eProducer chan ExtractResult) {
		for _, tx := range mtxs {
			bs.extractingCH <- struct{}{}

			go func(mTx *Transfer, end chan struct{}, mProducer chan<- ExtractResult) {
				//导出提出的交易
				mProducer <- bs.ExtractTransaction(mTx, blockTime, bs.ScanTargetFuncV2)
				//释放
				<-end

			}(tx, bs.extractingCH, eProducer)
		}
	}
	/*	开启导出的线程	*/

	//独立线程运行消费
	go saveWork(blockHeight, worker)

	//独立线程运行生产
	go extractWork(transfers, producer)

	//以下使用生产消费模式
	bs.extractRuntime(producer, worker, quit)

	if failed > 0 {
		return fmt.Errorf("block scanner saveWork failed")
	}

	return nil
}

//extractRuntime 提取运行时
func (bs *BlockScanner) extractRuntime(producer chan ExtractResult, worker chan ExtractResult, quit chan struct{}) {

	var (
		values = make([]ExtractResult, 0)
	)

	for {
		var activeWorker chan<- ExtractResult
		var activeValue ExtractResult
		//当数据队列有数据时，释放顶部，传输给消费者
		if len(values) > 0 {
			activeWorker = worker
			activeValue = values[0]
		}
		select {
		//生成者不断生成数据，插入到数据队列尾部
		case pa := <-producer:
			values = append(values, pa)
		case <-quit:
			//退出
			return
		case activeWorker <- activeValue:
			values = values[1:]
		}
	}
	//return
}

// ExtractTransaction 提取交易单
func (bs *BlockScanner) ExtractTransaction(tx *Transfer, blockTime int64, scanTargetFunc openwallet.BlockScanTargetFuncV2) ExtractResult {
	var (
		result = ExtractResult{
			TxID:        tx.DeployHash,
			extractData: make(map[string]*openwallet.TxExtractData),
			Success:     true,
		}
	)

	result.BlockHash = tx.BlockHash
	result.BlockHeight = tx.BlockHeight
	result.BlockTime = blockTime

	if scanTargetFunc == nil {
		bs.wm.Log.Std.Error("scanTargetFunc is not configurated")
		result.Success = false
		return result
	}

	// 删去prefix
	from := tx.From
	to := tx.To

	targetResult1 := scanTargetFunc(openwallet.ScanTargetParam{
		ScanTarget:     from,
		Symbol:         bs.wm.Symbol(),
		ScanTargetType: openwallet.ScanTargetTypeAddressMemo,
	})
	//订阅地址为交易单中的接收者
	targetResult2 := scanTargetFunc(openwallet.ScanTargetParam{
		ScanTarget:     to,
		Symbol:         bs.wm.Symbol(),
		ScanTargetType: openwallet.ScanTargetTypeAddressMemo,
	})

	//相同账户
	if targetResult1.SourceKey == targetResult2.SourceKey && len(targetResult1.SourceKey) > 0 && len(targetResult2.SourceKey) > 0 {
		bs.InitExtractResult(&targetResult1, &targetResult2, tx, &result, 0)
	} else {
		if targetResult1.Exist {
			bs.InitExtractResult(&targetResult1, nil, tx, &result, 1)
		}

		if targetResult2.Exist {
			bs.InitExtractResult(&targetResult2, nil, tx, &result, 2)
		}
	}

	return result

}

//InitExtractResult optType = 0: 输入输出提取，1: 输入提取，2：输出提取
func (bs *BlockScanner) InitExtractResult(source1 *openwallet.ScanTargetResult, source2 *openwallet.ScanTargetResult, tx *Transfer, result *ExtractResult, optType int64) {

	txExtractData := result.extractData[source1.SourceKey]
	if txExtractData == nil {
		txExtractData = &openwallet.TxExtractData{}
	}

	status := "1"
	reason := ""
	from := ""
	to := ""

	coin := openwallet.Coin{
		Symbol:     bs.wm.Symbol(),
		IsContract: false,
	}

	if optType == 0 {
		addr1, ok1 := source1.TargetInfo.(*openwallet.Address)
		if ok1 {
			from = addr1.Address
		} else {
			from = tx.From
		}

		addr2, ok1 := source2.TargetInfo.(*openwallet.Address)
		if ok1 {
			to = addr2.Address
		} else {
			to = tx.To
		}
	} else if optType == 1 {
		addr1, ok1 := source1.TargetInfo.(*openwallet.Address)
		if ok1 {
			from = addr1.Address
		} else {
			from = tx.From
		}
		to = tx.To
	} else if optType == 2 {
		addr2, ok2 := source1.TargetInfo.(*openwallet.Address)
		if ok2 {
			to = addr2.Address
		} else {
			to = tx.To
		}
		from = tx.From
	}

	transx := &openwallet.Transaction{
		Fees:        "0",
		Coin:        coin,
		BlockHash:   result.BlockHash,
		BlockHeight: result.BlockHeight,
		TxID:        result.TxID,
		Amount:      tx.Amount,
		ConfirmTime: result.BlockTime,
		From:        []string{from + ":" + tx.Amount},
		To:          []string{to + ":" + tx.Amount},
		IsMemo:      true,
		Status:      status,
		Reason:      reason,
		TxType:      0,
	}

	wxID := openwallet.GenTransactionWxID(transx)
	transx.WxID = wxID

	txExtractData.Transaction = transx
	if optType == 0 {
		bs.extractTxInput(tx, from, txExtractData)
		bs.extractTxOutput(tx, to, txExtractData)
	} else if optType == 1 {
		bs.extractTxInput(tx, from, txExtractData)
	} else if optType == 2 {
		bs.extractTxOutput(tx, to, txExtractData)
	}

	result.extractData[source1.SourceKey] = txExtractData
}

//extractTxInput 提取交易单输入部分,无需手续费，所以只包含1个TxInput
func (bs *BlockScanner) extractTxInput(trx *Transfer, from string, txExtractData *openwallet.TxExtractData) {

	tx := txExtractData.Transaction
	coin := tx.Coin

	//主网from交易转账信息，第一个TxInput
	txInput := &openwallet.TxInput{}
	txInput.Recharge.Sid = openwallet.GenTxInputSID(tx.TxID, bs.wm.Symbol(), "", uint64(0))
	txInput.Recharge.TxID = tx.TxID
	txInput.Recharge.Address = from
	txInput.Recharge.Coin = coin
	txInput.Recharge.Amount = tx.Amount
	txInput.Recharge.Symbol = coin.Symbol
	txInput.Recharge.BlockHash = tx.BlockHash
	txInput.Recharge.BlockHeight = tx.BlockHeight
	txInput.Recharge.Index = 0 //账户模型填0
	txInput.Recharge.CreateAt = time.Now().Unix()
	txInput.Recharge.TxType = tx.TxType
	txExtractData.TxInputs = append(txExtractData.TxInputs, txInput)
}

//extractTxOutput 提取交易单输入部分,只有一个TxOutPut
func (bs *BlockScanner) extractTxOutput(trx *Transfer, to string, txExtractData *openwallet.TxExtractData) {

	tx := txExtractData.Transaction
	coin := tx.Coin

	//主网to交易转账信息,只有一个TxOutPut
	txOutput := &openwallet.TxOutPut{}
	txOutput.Recharge.Sid = openwallet.GenTxOutPutSID(tx.TxID, bs.wm.Symbol(), "", uint64(0))
	txOutput.Recharge.TxID = tx.TxID
	txOutput.Recharge.Address = to
	txOutput.Recharge.Coin = coin
	txOutput.Recharge.Amount = tx.Amount
	txOutput.Recharge.Symbol = coin.Symbol
	txOutput.Recharge.BlockHash = tx.BlockHash
	txOutput.Recharge.BlockHeight = tx.BlockHeight
	txOutput.Recharge.Index = 0 //账户模型填0
	txOutput.Recharge.CreateAt = time.Now().Unix()
	txExtractData.TxOutputs = append(txExtractData.TxOutputs, txOutput)
}

//newExtractDataNotify 发送通知
func (bs *BlockScanner) newExtractDataNotify(height uint64, extractData map[string]*openwallet.TxExtractData) error {
	for o := range bs.Observers {
		for key, item := range extractData {
			err := o.BlockExtractDataNotify(key, item)
			if err != nil {
				log.Error("BlockExtractDataNotify unexpected error:", err)
				//记录未扫区块
				unscanRecord := openwallet.NewUnscanRecord(height, "", "ExtractData Notify failed.", bs.wm.Symbol())
				err = bs.SaveUnscanRecord(unscanRecord)
				if err != nil {
					log.Std.Error("block height: %d, save unscan record failed. unexpected error: %v", height, err.Error())
				}
			}
		}
	}

	return nil
}

//ScanBlock 扫描指定高度区块
func (bs *BlockScanner) ScanBlock(height uint64) error {

	block, err := bs.scanBlock(height)
	if err != nil {
		return err
	}

	//通知新区块给观测者，异步处理
	bs.newBlockNotify(block)

	return nil
}

func (bs *BlockScanner) scanBlock(height uint64) (*Block, error) {

	block, err := bs.wm.GetBlockByHeight(height)
	if err != nil {
		bs.wm.Log.Std.Info("block scanner can not get new block data; unexpected error: %v", err)

		//记录未扫区块
		unscanRecord := openwallet.NewUnscanRecord(height, "", err.Error(), bs.wm.Symbol())
		bs.SaveUnscanRecord(unscanRecord)
		bs.wm.Log.Std.Info("block height: %d extract failed.", height)
		return nil, err
	}

	bs.wm.Log.Std.Info("block scanner scanning height: %d ...", block.Height)

	err = bs.BatchExtractTransactions(block.Height, block.Hash, int64(block.Time))
	if err != nil {
		bs.wm.Log.Std.Info("block scanner can not extractRechargeRecords; unexpected error: %v", err)
	}

	return block, nil
}

//SetRescanBlockHeight 重置区块链扫描高度
func (bs *BlockScanner) SetRescanBlockHeight(height uint64) error {
	if height <= 0 {
		return fmt.Errorf("block height to rescan must greater than 0. ")
	}

	block, err := bs.wm.GetBlockByHeight(height - 1)
	if err != nil {
		return err
	}

	bs.SaveLocalBlockHead(height-1, block.Hash)

	return nil
}

// GetGlobalMaxBlockHeight GetGlobalMaxBlockHeight
func (bs *BlockScanner) GetGlobalMaxBlockHeight() uint64 {
	headBlock, err := bs.wm.GetLatestBlockInfo()
	if err != nil {
		bs.wm.Log.Std.Info("get global head block error;unexpected error:%v", err)
		return 0
	}
	return headBlock.Height
}

//GetScannedBlockHeight 获取已扫区块高度
func (bs *BlockScanner) GetScannedBlockHeight() uint64 {
	height, _, _ := bs.GetLocalBlockHead()
	return uint64(height)
}

//GetBalanceByAddress 查询地址余额
func (bs *BlockScanner) GetBalanceByAddress(address ...string) ([]*openwallet.Balance, error) {

	stateRootHash, err := bs.wm.GetStateRootHash()
	if err != nil {
		return nil, err
	}

	addrBalanceArr := make([]*openwallet.Balance, 0)
	for _, a := range address {
		balance, err := bs.wm.GetAccountBalance(stateRootHash, bs.wm.AddressToHash(a))
		if err == nil {
			obj := &openwallet.Balance{
				Symbol:           bs.wm.Symbol(),
				Address:          a,
				Balance:          balance.String(),
				UnconfirmBalance: "0",
				ConfirmBalance:   balance.String(),
			}

			addrBalanceArr = append(addrBalanceArr, obj)
			//return nil, err
		}

	}

	return addrBalanceArr, nil

	return addrBalanceArr, nil
}

func (bs *BlockScanner) GetCurrentBlockHeader() (*openwallet.BlockHeader, error) {
	latestBlock, err := bs.wm.GetLatestBlockInfo()
	if err != nil {
		bs.wm.Log.Std.Info("get chain info error;unexpected error:%v", err)
		return nil, err
	}
	return &openwallet.BlockHeader{Height: latestBlock.Height, Hash: latestBlock.Hash}, nil
}

//rescanFailedRecord 重扫失败记录
func (bs *BlockScanner) RescanFailedRecord() {

	var (
		blockMap = make(map[uint64][]string)
	)

	list, err := bs.BlockchainDAI.GetUnscanRecords(bs.wm.Symbol())
	if err != nil {
		bs.wm.Log.Std.Info("block scanner can not get rescan data; unexpected error: %v", err)
	}

	//组合成批处理
	for _, r := range list {

		if _, exist := blockMap[r.BlockHeight]; !exist {
			blockMap[r.BlockHeight] = make([]string, 0)
		}

		if len(r.TxID) > 0 {
			arr := blockMap[r.BlockHeight]
			arr = append(arr, r.TxID)

			blockMap[r.BlockHeight] = arr
		}
	}

	for height, _ := range blockMap {

		if height == 0 {
			continue
		}

		bs.wm.Log.Std.Info("block scanner rescanning height: %d ...", height)

		block, err := bs.wm.GetBlockByHeight(height)
		if err != nil {
			bs.wm.Log.Std.Info("block scanner can not get new block data; unexpected error: %v", err)
			continue
		}

		err = bs.BatchExtractTransactions(height, block.Hash, int64(block.Time))
		if err != nil {
			bs.wm.Log.Std.Info("block scanner can not extractRechargeRecords; unexpected error: %v", err)
			continue
		}

		//删除未扫记录
		bs.DeleteUnscanRecord(height)
	}
}

//ExtractTransactionData 扫描一笔交易
func (bs *BlockScanner) ExtractTransactionData(txid string, scanTargetFunc openwallet.BlockScanTargetFunc) (map[string][]*openwallet.TxExtractData, error) {

	scanTargetFuncV2 := func(target openwallet.ScanTargetParam) openwallet.ScanTargetResult {
		sourceKey, ok := scanTargetFunc(openwallet.ScanTarget{
			Address:          target.ScanTarget,
			Symbol:           bs.wm.Symbol(),
			BalanceModelType: bs.wm.BalanceModelType(),
		})
		return openwallet.ScanTargetResult{
			SourceKey: sourceKey,
			Exist:     ok,
		}
	}

	deployInnfo, err := bs.wm.GetDeployInfo(txid)
	if err != nil {
		return nil, err
	}

	blockHash := deployInnfo.Get("execution_results").Array()[0].Get("block_hash").String()

	block, err := bs.wm.GetBlockByHash(blockHash)
	if err != nil {
		return nil, err
	}

	transfers, err := bs.wm.GetBlockTransfers(block.Height)
	if err != nil {
		return nil, err
	}

	var findTx *Transfer
	for _, tx := range transfers {
		if tx.DeployHash == txid {
			findTx = tx
			break
		}
	}

	if findTx == nil {
		return nil, fmt.Errorf("can not find txid: %s", txid)
	}

	result := bs.ExtractTransaction(findTx, int64(block.Time), scanTargetFuncV2)
	if !result.Success {
		return nil, fmt.Errorf("extract transaction failed")
	}
	extData := make(map[string][]*openwallet.TxExtractData)
	for key, data := range result.extractData {
		txs := extData[key]
		if txs == nil {
			txs = make([]*openwallet.TxExtractData, 0)
		}
		txs = append(txs, data)
		extData[key] = txs
	}
	return extData, nil
}

//SupportBlockchainDAI 支持外部设置区块链数据访问接口
//@optional
func (bs *BlockScanner) SupportBlockchainDAI() bool {
	return true
}
