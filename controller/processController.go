package controller

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	log "github.com/LACNetNetworks/gas-relay-signer/audit"
	"github.com/LACNetNetworks/gas-relay-signer/model"
	"github.com/LACNetNetworks/gas-relay-signer/rpc"
	"github.com/LACNetNetworks/gas-relay-signer/service"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

const PENDING = "PENDING"
const LATEST = "LATEST"

func processGetTransactionReceipt(relaySignerService *service.RelaySignerService, rpcMessage rpc.JsonrpcMessage, w http.ResponseWriter) {
	log.GeneralLogger.Println("Is getTransactionReceipt")
	var params []string
	err := json.Unmarshal(rpcMessage.Params, &params)
	if err != nil {
		log.GeneralLogger.Println(err)
		err := errors.New("internal error")
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}
	response := relaySignerService.GetTransactionReceipt(rpcMessage.ID, params[0][2:])
	data, err := json.Marshal(response)
	if err != nil {
		log.GeneralLogger.Println(err)
		err := errors.New("internal error")
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}
	w.Write(data)
}

func processTransactionCount(relaySignerService *service.RelaySignerService, rpcMessage rpc.JsonrpcMessage, w http.ResponseWriter) {
	log.GeneralLogger.Println("Is getTransactionCount")
	var params []string
	err := json.Unmarshal(rpcMessage.Params, &params)
	if err != nil {
		log.GeneralLogger.Println(err)
		err := errors.New("internal error")
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}

	var response *rpc.JsonrpcMessage

	if len(params) > 1 {
		if strings.ToUpper(params[1]) == PENDING {
			response = relaySignerService.GetTransactionCount(rpcMessage.ID, params[0], true)
		} else if strings.ToUpper(params[1]) == LATEST {
			response = relaySignerService.GetTransactionCount(rpcMessage.ID, params[0], false)
		} else {
			err := errors.New("parameter not defined, only pending or latest are allowed")
			data := handleError(rpcMessage.ID, err)
			w.Write(data)
		}
	} else {
		response = relaySignerService.GetTransactionCount(rpcMessage.ID, params[0], false)
	}

	data, err := json.Marshal(response)
	if err != nil {
		log.GeneralLogger.Println(err)
		err := errors.New("internal error")
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}
	w.Write(data)
}

func processRawTransaction(relaySignerService *service.RelaySignerService, rpcMessage rpc.JsonrpcMessage, w http.ResponseWriter) {
	log.GeneralLogger.Println("Is a rawTransaction")
	var params []string
	err := json.Unmarshal(rpcMessage.Params, &params)
	if err != nil {
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}

	decodeTransaction, err := service.GetTransaction(params[0][2:])
	if err != nil {
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}

	v, rInt, sInt := decodeTransaction.RawSignatureValues()
	if (v == nil) || (rInt == nil) || (sInt == nil) {
		err := errors.New("bad signature ECDSA")
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}

	message, err := decodeTransaction.AsMessage(types.NewEIP155Signer(decodeTransaction.ChainId()))
	if err != nil {
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}

	if relaySignerService.Config.Security.PermissionsEnabled {
		isSenderPermitted, err := relaySignerService.VerifySender(message.From(), rpcMessage.ID)
		if err != nil {
			data := handleError(rpcMessage.ID, err)
			w.Write(data)
			return
		}
		if !isSenderPermitted {
			err := errors.New("account sender is not permitted to send transactions")
			data := handleError(rpcMessage.ID, err)
			w.Write(data)
			return
		}
	}

	var metaTxGasLimit uint64 = uint64((len(decodeTransaction.Data())*105)+300000) + decodeTransaction.Gas()

	lock.Lock()
	defer lock.Unlock()
	isCorrectGasLimit, err := relaySignerService.VerifyGasLimit(metaTxGasLimit, rpcMessage.ID)
	if err != nil {
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}
	if !isCorrectGasLimit {
		err := errors.New("transaction gas limit exceeds block gas limit")
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}

	log.GeneralLogger.Println("From:", message.From().Hex())
	if decodeTransaction.To() != nil {
		log.GeneralLogger.Println("To:", decodeTransaction.To().Hex())
	}
	log.GeneralLogger.Println("Data:", hexutil.Encode(decodeTransaction.Data()))
	log.GeneralLogger.Println("GasLimit:", decodeTransaction.Gas())
	log.GeneralLogger.Println("Nonce", decodeTransaction.Nonce())
	log.GeneralLogger.Println("GasPrice:", decodeTransaction.GasPrice())
	log.GeneralLogger.Println("Value:", decodeTransaction.Value())

	var r [32]byte
	var s [32]byte
	rBytes, _ := hex.DecodeString(fmt.Sprintf("%064x", rInt))
	sBytes, _ := hex.DecodeString(fmt.Sprintf("%064x", sInt))

	copy(r[:], rBytes)
	copy(s[:], sBytes)

	var signingDataTx *model.RawTransaction

	if decodeTransaction.To() != nil {
		signingDataTx = model.NewTransaction(decodeTransaction.Nonce(), *decodeTransaction.To(), decodeTransaction.Value(), decodeTransaction.Gas(), decodeTransaction.GasPrice(), decodeTransaction.Data())
	} else {
		signingDataTx = model.NewContractCreation(decodeTransaction.Nonce(), decodeTransaction.Value(), decodeTransaction.Gas(), decodeTransaction.GasPrice(), decodeTransaction.Data())
	}

	signingDataRLP, err := rlp.EncodeToBytes(signingDataTx.Data)
	if err != nil {
		err := errors.New("internal error")
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}

	response := relaySignerService.SendMetatransaction(rpcMessage.ID, decodeTransaction.To(), metaTxGasLimit, signingDataRLP, uint8(v.Uint64()), r, s, message.From().Hex(), decodeTransaction.Nonce())
	data, err := json.Marshal(response)
	if err != nil {
		log.GeneralLogger.Println(err)
		err := errors.New("internal error")
		data := handleError(rpcMessage.ID, err)
		w.Write(data)
		return
	}
	w.Write(data)
}
