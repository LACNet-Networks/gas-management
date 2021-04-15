/*
Copyright © 2020 Adrian Pareja <adriancc5.5@gmail.com>
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"os"
	"net/http"
	"github.com/spf13/viper"
	"github.com/lacchain/gas-relay-signer/model"
	"github.com/lacchain/gas-relay-signer/service"
	"github.com/lacchain/gas-relay-signer/controller"
	log "github.com/lacchain/gas-relay-signer/audit"
)

var config *model.Config
var relaySignerService *service.RelaySignerService
var relayController *controller.RelayController

func main() {
	config = getConfigFromFile()

	relaySignerService = new(service.RelaySignerService)
	err := relaySignerService.Init(config)
	if err != nil{
		log.GeneralLogger.Fatal(err)
		return
	}

	relayController = new(controller.RelayController)
	relayController.Init(config, relaySignerService)
	setupRoutes(config.Application.Port)
}

func getConfigFromFile()(*model.Config){
	v := viper.New()
	v.SetConfigName("config")
	v.AddConfigPath(".")
	if err := v.ReadInConfig(); err != nil {
		log.GeneralLogger.Printf("couldn't load config: %s", err)
		os.Exit(1)
	}
	var c model.Config
	if err := v.Unmarshal(&c); err != nil {
		log.GeneralLogger.Printf("couldn't read config: %s", err)
		os.Exit(1)
	}
	log.GeneralLogger.Printf("smartContract=%s AgentKey=%s\n", c.Application.ContractAddress, c.KeyStore.Agent)
	return &c
}

func setupRoutes(port string) {
	log.GeneralLogger.Println("Init RelaySigner")
	http.HandleFunc("/", relayController.SignTransaction)
	http.ListenAndServe(":"+port, nil)
}