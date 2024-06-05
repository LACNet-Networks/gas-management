/*
	RelaySigner Service
	version 0.9
	author: Adrian Pareja Abarca
	email: adriancc5.5@gmail.com
*/

package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"

	log "github.com/LACNetNetworks/gas-relay-signer/audit"
	bl "github.com/LACNetNetworks/gas-relay-signer/blockchain"
	"github.com/LACNetNetworks/gas-relay-signer/errors"
	"github.com/LACNetNetworks/gas-relay-signer/model"
	"github.com/LACNetNetworks/gas-relay-signer/rpc"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	sha "golang.org/x/crypto/sha3"
)

const RelayABI = "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"_blocksFrequency\",\"type\":\"uint8\"},{\"internalType\":\"address\",\"name\":\"_accountIngress\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"admin\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"newAddress\",\"type\":\"address\"}],\"name\":\"AccountIngressChanged\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"node\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"originalSender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"enumIRelayHub.ErrorCode\",\"name\":\"errorCode\",\"type\":\"uint8\"}],\"name\":\"BadTransactionSent\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"admin\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"blocksFrequency\",\"type\":\"uint8\"}],\"name\":\"BlockFrequencyChanged\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"relay\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"contractDeployed\",\"type\":\"address\"}],\"name\":\"ContractDeployed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"node\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"blockNumber\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"countExceeded\",\"type\":\"uint8\"}],\"name\":\"GasLimitExceeded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"blockNumber\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"gasUsedLastBlocks\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"averageLastBlocks\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"newGasLimit\",\"type\":\"uint256\"}],\"name\":\"GasLimitSet\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"node\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"blockNumber\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"gasUsed\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"gasLimit\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"gasUsedLastBlocks\",\"type\":\"uint256\"}],\"name\":\"GasUsedByTransaction\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"admin\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"gasUsedRelayHub\",\"type\":\"uint256\"}],\"name\":\"GasUsedRelayHubChanged\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"blockNumber\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"admin\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"maxGasBlockLimit\",\"type\":\"uint256\"}],\"name\":\"MaxGasBlockLimitChanged\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"newNode\",\"type\":\"address\"}],\"name\":\"NodeAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"node\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"blockNumber\",\"type\":\"uint256\"}],\"name\":\"NodeBlocked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"oldNode\",\"type\":\"address\"}],\"name\":\"NodeDeleted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"gasLimit\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"decodedFunction\",\"type\":\"bytes\"}],\"name\":\"Parameters\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"result\",\"type\":\"bool\"}],\"name\":\"Recalculated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"}],\"name\":\"Relayed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"previousAdminRole\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"newAdminRole\",\"type\":\"bytes32\"}],\"name\":\"RoleAdminChanged\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"}],\"name\":\"RoleGranted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"}],\"name\":\"RoleRevoked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"relay\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"executed\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"output\",\"type\":\"bytes\"}],\"name\":\"TransactionRelayed\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"DEFAULT_ADMIN_ROLE\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newNode\",\"type\":\"address\"}],\"name\":\"addNode\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"node\",\"type\":\"address\"}],\"name\":\"deleteNode\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getGasLimit\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getGasUsedLastBlocks\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getNodes\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"}],\"name\":\"getRoleAdmin\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getRoleMember\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"}],\"name\":\"getRoleMemberCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"grantRole\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"hasRole\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"renounceRole\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"revokeRole\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_accountIngress\",\"type\":\"address\"}],\"name\":\"setAccounIngress\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"_blocksFrequency\",\"type\":\"uint8\"}],\"name\":\"setBlocksFrequency\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"newGasUsed\",\"type\":\"uint256\"}],\"name\":\"setGasUsedLastBlocks\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_gasUsedRelayHub\",\"type\":\"uint256\"}],\"name\":\"setGasUsedRelayHub\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_maxGasBlockLimit\",\"type\":\"uint256\"}],\"name\":\"setMaxGasBlockLimit\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"signingData\",\"type\":\"bytes\"},{\"internalType\":\"uint8\",\"name\":\"v\",\"type\":\"uint8\"},{\"internalType\":\"bytes32\",\"name\":\"r\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"s\",\"type\":\"bytes32\"}],\"name\":\"relayMetaTx\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"success\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"signingData\",\"type\":\"bytes\"},{\"internalType\":\"uint8\",\"name\":\"v\",\"type\":\"uint8\"},{\"internalType\":\"bytes32\",\"name\":\"r\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"s\",\"type\":\"bytes32\"}],\"name\":\"deployMetaTx\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"success\",\"type\":\"bool\"},{\"internalType\":\"address\",\"name\":\"deployedAddress\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"}],\"name\":\"getNonce\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getMsgSender\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"gasUsed\",\"type\":\"uint256\"}],\"name\":\"increaseGasUsed\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

const ENVIRONMENT_KEY_NAME = "WRITER_KEY"

var GAS_LIMIT uint64 = 0

var lock sync.Mutex

// RelaySignerService is the main service
type RelaySignerService struct {
	// The service's configuration
	Config  *model.Config
	senders map[string]*big.Int
}

// Init configuration parameters
func (service *RelaySignerService) Init(_config *model.Config) error {
	service.Config = _config

	key, exist := os.LookupEnv(ENVIRONMENT_KEY_NAME)
	if !exist {
		return errors.FailedReadEnv.New("Environment variable WRITER_KEY not set", -32602)
	}

	privateKey, err := crypto.HexToECDSA(string(key[2:66]))
	if err != nil {
		return errors.FailedKeyConfig.New("Invalid ECDSA Key", -32602)
	}

	publicKey := privateKey.Public()
	_, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.FailedKeyConfig.New("Invalid ECDSA Public Key", -32602)
	}

	service.Config.Application.Key = string(key[2:66])

	service.senders = make(map[string]*big.Int)

	if service.Config.Security.PermissionsEnabled {
		if !(common.IsHexAddress(service.Config.Security.AccountContractAddress)) {
			return errors.InvalidAddress.New("Invalid Account Smart Contract Address", -32608)
		}
	}

	service.Config.Application.RelayHubContractAddress, err = getRelayHubContractAddress(service.Config.Application.NodeURL, "1000", service.Config.Application.ContractAddress, 10)
	if err != nil {
		return errors.FailedKeyConfig.New("Can't get relayHub smart contract address from Proxy", -32610)
	}

	return nil
}

// SendMetatransaction to blockchain
func (service *RelaySignerService) SendMetatransaction(id json.RawMessage, to *common.Address, gasLimit uint64, signingData []byte, v uint8, r, s [32]byte, sender string, nonce uint64) *rpc.JsonrpcMessage {
	client := new(bl.Client)
	err := client.Connect(service.Config.Application.NodeURL)
	if err != nil {
		HandleError(id, err)
	}
	defer client.Close()

	privateKey, err := crypto.HexToECDSA(service.Config.Application.Key)
	if err != nil {
		HandleError(id, err)
	}

	optionsSendTransaction, err := client.ConfigTransaction(privateKey, gasLimit, true)
	if err != nil {
		return HandleError(id, err)
	}
	tx, err := client.SendMetatransaction(*service.Config.Application.RelayHubContractAddress, optionsSendTransaction, to, signingData, v, r, s)
	if err != nil {
		return HandleError(id, err)
	}

	log.GeneralLogger.Println("transaction", tx)

	service.incrementTransactionCount(sender, nonce)

	result := new(rpc.JsonrpcMessage)

	result.ID = id
	return result.Response(tx)
}

// GetTransactionReceipt from blockchain
func (service *RelaySignerService) GetTransactionReceipt(id json.RawMessage, transactionID string) *rpc.JsonrpcMessage {
	client := new(bl.Client)
	err := client.Connect(service.Config.Application.NodeURL)
	if err != nil {
		HandleError(id, err)
	}
	defer client.Close()

	receipt, err := client.GetTransactionReceipt(common.HexToHash(transactionID))
	if err != nil {
		HandleError(id, err)
	}

	var receiptReverted map[string]interface{}

	if receipt != nil {
		d := sha.NewLegacyKeccak256()
		e := sha.NewLegacyKeccak256()
		f := sha.NewLegacyKeccak256()

		d.Write([]byte("ContractDeployed(address,address,address)"))

		eventContractDeployed := hex.EncodeToString(d.Sum(nil))

		e.Write([]byte("TransactionRelayed(address,address,address,bool,bytes)"))
		eventTransactionRelayed := hex.EncodeToString(e.Sum(nil))

		f.Write([]byte("BadTransactionSent(address,address,uint8)"))
		//eventBadTransaction := hex.EncodeToString(f.Sum(nil))

		fmt.Println("deployed contract eventKeccak:", eventContractDeployed)
		fmt.Println("transaction relayed eventKeccak:", eventTransactionRelayed)

		for _, log := range receipt.Logs {
			if log.Topics[0].Hex() == "0x"+eventContractDeployed {
				receipt.ContractAddress = common.BytesToAddress(log.Data)
			}
			if log.Topics[0].Hex() == "0x"+eventTransactionRelayed {
				executed, output := transactionRelayedFailed(id, log.Data)
				if !executed {
					receipt.Status = uint64(0)
					fmt.Println("Reverse Error:", hexutil.Encode(output))

					jsonReceipt, err := json.Marshal(receipt)
					if err != nil {
						HandleError(id, err)
					}

					json.Unmarshal(jsonReceipt, &receiptReverted)
					receiptReverted["revertReason"] = hexutil.Encode(output)
				}
			}
			/*		if log.Topics[0].Hex() == "0x"+eventBadTransaction {
					receipt.Status = uint64(0)
					jsonReceipt, err := json.Marshal(receipt)
					if err != nil {
						HandleError(id, err)
					}

					json.Unmarshal(jsonReceipt, &receiptReverted)
					output := getBadTransaction(id, log.Data)
					receiptReverted["revertReason"] = hexutil.Encode(output)
				}*/
		}
	}
	result := new(rpc.JsonrpcMessage)

	result.ID = id
	if receiptReverted != nil {
		return result.Response(receiptReverted)
	}
	return result.Response(receipt)

}

// GetTransactionCount of account
func (service *RelaySignerService) GetTransactionCount(id json.RawMessage, from string, isPending bool) *rpc.JsonrpcMessage {
	var count *big.Int
	if isPending && (service.senders[from] != nil) {
		count = service.senders[from]
	} else {
		client := new(bl.Client)
		err := client.Connect(service.Config.Application.NodeURL)
		if err != nil {
			HandleError(id, err)
		}
		defer client.Close()

		privateKey, err := crypto.HexToECDSA(service.Config.Application.Key)
		if err != nil {
			HandleError(id, err)
		}

		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			err := errors.New("error casting public key to ECDSA", -32602)
			HandleError(id, err)
		}

		nodeAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

		address := common.HexToAddress(from)

		count, err = client.GetTransactionCount(*service.Config.Application.RelayHubContractAddress, address, nodeAddress)
		if err != nil {
			HandleError(id, err)
		}
	}

	result := new(rpc.JsonrpcMessage)

	result.ID = id
	return result.Response(fmt.Sprintf("0x%x", count))
}

// VerifyGasLimit sent a transaction
func (service *RelaySignerService) VerifyGasLimit(gasLimit uint64, id json.RawMessage) (bool, error) {
	client := new(bl.Client)
	err := client.Connect(service.Config.Application.NodeURL)
	if err != nil {
		return false, err
	}
	defer client.Close()

	privateKey, err := crypto.HexToECDSA(service.Config.Application.Key)
	if err != nil {
		HandleError(id, err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		err := errors.New("error casting public key to ECDSA", -32602)
		HandleError(id, err)
	}

	nodeAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	currentGasLimit, err := client.GetNodeGasLimit(*service.Config.Application.RelayHubContractAddress, nodeAddress)
	if err != nil {
		return false, err
	}

	if currentGasLimit != nil {
		log.GeneralLogger.Println("current gasLimit assigned:", currentGasLimit.Uint64())
	}
	if increment(gasLimit) > currentGasLimit.Uint64() {
		return false, nil
	}

	return true, nil
}

// VerifySender sent a transaction
func (service *RelaySignerService) VerifySender(sender common.Address, id json.RawMessage) (bool, error) {
	client := new(bl.Client)
	err := client.Connect(service.Config.Application.NodeURL)
	if err != nil {
		return false, err
	}
	defer client.Close()

	contractAddress := common.HexToAddress(service.Config.Security.AccountContractAddress)

	isPermitted, err := client.AccountPermitted(contractAddress, sender)
	if err != nil {
		return false, err
	}

	log.GeneralLogger.Println("sender is permitted:", isPermitted)

	return isPermitted, nil
}

// DecreaseGasUsed by node
func (service *RelaySignerService) DecreaseGasUsed(id json.RawMessage) bool {
	client := new(bl.Client)
	err := client.Connect(service.Config.Application.NodeURL)
	if err != nil {
		HandleError(id, err)
	}
	defer client.Close()

	privateKey, err := crypto.HexToECDSA(service.Config.Application.Key)
	if err != nil {
		log.GeneralLogger.Fatal(err)
	}

	options, err := client.ConfigTransaction(privateKey, 30000, false)
	if err != nil {
		HandleError(id, err)
	}

	_, err = client.DecreaseGasUsed(*service.Config.Application.RelayHubContractAddress, options, new(big.Int).SetUint64(25000))
	if err != nil {
		HandleError(id, err)
	}

	return true
}

func transactionRelayedFailed(id json.RawMessage, data []byte) (bool, []byte) {
	var transactionRelayedEvent struct {
		Relay    common.Address
		From     common.Address
		To       common.Address
		Executed bool
		Output   []byte
	}

	relayHubAbi, err := abi.JSON(strings.NewReader(RelayABI))
	if err != nil {
		HandleError(id, err)
	}

	err = relayHubAbi.Unpack(&transactionRelayedEvent, "TransactionRelayed", data)

	if err != nil {
		HandleError(id, err)
	}

	return transactionRelayedEvent.Executed, transactionRelayedEvent.Output
}

func getBadTransaction(id json.RawMessage, data []byte) []byte {
	var badTransactionEvent struct {
		Node           common.Address
		OriginalSender common.Address
		ErrorCode      uint8
	}

	relayHubAbi, err := abi.JSON(strings.NewReader(RelayABI))
	if err != nil {
		HandleError(id, err)
	}

	err = relayHubAbi.Unpack(&badTransactionEvent, "BadTransactionSent", data)

	if err != nil {
		HandleError(id, err)
	}

	switch badTransactionEvent.ErrorCode {
	case 0:
		return []byte("Max block gas limit overpassed")
	case 1:
		return []byte("Original sender is different who signed the transaction")
	case 2:
		return []byte("Bad nonce assigned")
	case 3:
		return []byte("Not enough gas to process the transaction")
	case 4:
		return []byte("Destination is an empty contract")
	case 5:
		return []byte("Your bytecode to deploy is empty")
	case 6:
		return []byte("Invalid Signature")
	case 7:
		return []byte("Destination is not allowed")
	}

	return nil
}

func (service *RelaySignerService) ProcessNewBlocks(done <-chan interface{}) {
	fmt.Println("Initiating process BLOCKSSS")
	client := new(bl.Client)
	err := client.Connect(service.Config.Application.WSURL)
	if err != nil {
		log.GeneralLogger.Fatal(err)
	}
	defer client.Close()

	headers := make(chan *types.Header)
	sub, err := client.GetEthclient().SubscribeNewHead(context.Background(), headers)
	if err != nil {
		log.GeneralLogger.Fatal(err)
	}

	for {
		select {
		case err := <-sub.Err():
			log.GeneralLogger.Println("WebSocket Failed")
			log.GeneralLogger.Fatal(err)
		case header := <-headers:
			log.GeneralLogger.Println("new block generated:", header.Hash().Hex())
			decrement()
		case <-done:
			log.GeneralLogger.Println("quit signal received...exiting from processing blocks")
			return
		}
	}
}

func increment(gasLimit uint64) uint64 {
	lock.Lock()
	defer lock.Unlock()
	GAS_LIMIT = GAS_LIMIT + gasLimit
	log.GeneralLogger.Println("gasLimit used in currently block:", GAS_LIMIT)
	return GAS_LIMIT
}

func decrement() {
	lock.Lock()
	defer lock.Unlock()
	GAS_LIMIT = 0
	log.GeneralLogger.Println("gas limit was reseted to 0")
}

func (service *RelaySignerService) incrementTransactionCount(from string, nonce uint64) {
	if service.senders[from] != nil && nonce >= service.senders[from].Uint64() {
		newNonce := service.senders[from].Uint64() + 1
		service.senders[from].SetUint64(newNonce)
	} else {
		service.senders[from] = new(big.Int).SetUint64(nonce)
	}
}

// HandleError
func HandleError(id json.RawMessage, err error) *rpc.JsonrpcMessage {
	log.GeneralLogger.Println(err.Error())
	result := new(rpc.JsonrpcMessage)
	result.ID = id
	return result.ErrorResponse(err)
}
