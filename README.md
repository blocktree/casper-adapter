# metaverse-adapter

metaverse-adapter适配了openwallet.AssetsAdapter接口，给应用提供了底层的区块链协议支持。

## 如何测试

openwtester包下的测试用例已经集成了openwallet钱包体系，创建conf文件，新建ETP.ini文件，编辑如下内容：

```ini

# node api url
serverAPI = "http://127.0.0.1:7777/rpc"
# minimum transaction fees
minFees = "0.00001"
# The minimum amount in motes for a valid native transfer.
transferMinimumMotes = "2.5"
# mainnet
networkName = "casper
# Cache data file directory, default = "", current directory: ./data
dataDir = ""

```
