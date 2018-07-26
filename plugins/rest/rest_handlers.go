// Copyright (c) 2017 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:generate go-bindata-assetfs -pkg rest -o bindata.go ./templates/...

package rest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	govppapi "git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/core/bin_api/vpe"
	"github.com/gorilla/mux"
	"github.com/ligato/vpp-agent/plugins/govppmux/vppcalls"
	"github.com/unrolled/render"

	"github.com/ligato/vpp-agent/plugins/rest/url"
	aclcalls "github.com/ligato/vpp-agent/plugins/vpp/aclplugin/vppcalls"
	l3plugin "github.com/ligato/vpp-agent/plugins/vpp/l3plugin/vppcalls"
	"github.com/ligato/vpp-agent/plugins/vpp/model/acl"
	"github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
)

// Registers access list REST handlers
func (plugin *Plugin) registerAccessListHandlers() error {
	// GET IP ACLs
	plugin.registerHTTPHandler(url.RestIPKey(), GET, func() (interface{}, error) {
		return plugin.aclHandler.DumpIPACL(nil)
	})
	// GET MACIP ACLs
	plugin.registerHTTPHandler(url.RestMACIPKey(), GET, func() (interface{}, error) {
		return plugin.aclHandler.DumpMacIPAcls()
	})
	// GET IP ACL example
	plugin.HTTPHandlers.RegisterHTTPHandler(url.RestIPExampleKey(), plugin.exampleIpACLGetHandler, GET)
	// GET MACIP ACL example
	plugin.HTTPHandlers.RegisterHTTPHandler(url.RestMACIPExampleKey(), plugin.exampleMacIpACLGetHandler, GET)

	return nil
}

// Registers interface REST handlers
func (plugin *Plugin) registerInterfaceHandlers() error {
	// GET all interfaces
	plugin.registerHTTPHandler(url.RestInterfaceKey(), GET, func() (interface{}, error) {
		return plugin.ifHandler.DumpInterfaces()
	})
	// GET loopback interfaces
	plugin.registerHTTPHandler(url.RestLoopbackKey(), GET, func() (interface{}, error) {
		ifs, err := plugin.ifHandler.DumpInterfaces()
		for ifKey, ifConfig := range ifs {
			if ifConfig.Interface.Type != interfaces.InterfaceType_SOFTWARE_LOOPBACK {
				delete(ifs, ifKey)
			}
		}
		return ifs, err
	})
	// GET ethernet interfaces
	plugin.registerHTTPHandler(url.RestEthernetKey(), GET, func() (interface{}, error) {
		ifs, err := plugin.ifHandler.DumpInterfaces()
		for ifKey, ifConfig := range ifs {
			if ifConfig.Interface.Type != interfaces.InterfaceType_ETHERNET_CSMACD {
				delete(ifs, ifKey)
			}
		}
		return ifs, err
	})
	// GET memif interfaces
	plugin.registerHTTPHandler(url.RestMemifKey(), GET, func() (interface{}, error) {
		ifs, err := plugin.ifHandler.DumpInterfaces()
		for ifKey, ifConfig := range ifs {
			if ifConfig.Interface.Type != interfaces.InterfaceType_MEMORY_INTERFACE {
				delete(ifs, ifKey)
			}
		}
		return ifs, err
	})
	// GET tap interfaces
	plugin.registerHTTPHandler(url.RestTapKey(), GET, func() (interface{}, error) {
		ifs, err := plugin.ifHandler.DumpInterfaces()
		for ifKey, ifConfig := range ifs {
			if ifConfig.Interface.Type != interfaces.InterfaceType_TAP_INTERFACE {
				delete(ifs, ifKey)
			}
		}
		return ifs, err
	})
	// GET af-packet interfaces
	plugin.registerHTTPHandler(url.RestAfPAcketKey(), GET, func() (interface{}, error) {
		ifs, err := plugin.ifHandler.DumpInterfaces()
		for ifKey, ifConfig := range ifs {
			if ifConfig.Interface.Type != interfaces.InterfaceType_AF_PACKET_INTERFACE {
				delete(ifs, ifKey)
			}
		}
		return ifs, err
	})
	// GET VxLAN interfaces
	plugin.registerHTTPHandler(url.RestVxLanKey(), GET, func() (interface{}, error) {
		ifs, err := plugin.ifHandler.DumpInterfaces()
		for ifKey, ifConfig := range ifs {
			if ifConfig.Interface.Type != interfaces.InterfaceType_VXLAN_TUNNEL {
				delete(ifs, ifKey)
			}
		}
		return ifs, err
	})

	return nil
}

func (plugin *Plugin) registerBfdHandlers() error {
	// GET BFD configuration
	plugin.registerHTTPHandler(url.RestBfdKey(), GET, func() (interface{}, error) {
		return plugin.bfdHandler.DumpBfdSingleHop()
	})
	// GET BFD sessions
	plugin.registerHTTPHandler(url.RestSessionKey(), GET, func() (interface{}, error) {
		return plugin.bfdHandler.DumpBfdSessions()
	})
	// GET BFD authentication keys
	plugin.registerHTTPHandler(url.RestAuthKeysKey(), GET, func() (interface{}, error) {
		return plugin.bfdHandler.DumpBfdAuthKeys()
	})

	return nil
}

// Registers L2 plugin REST handlers
func (plugin *Plugin) registerL2Handlers() error {
	// GET bridge domain IDs
	plugin.registerHTTPHandler(url.RestBridgeDomainIDKey(), GET, func() (interface{}, error) {
		return plugin.bdHandler.DumpBridgeDomainIDs()
	})
	// GET bridge domains
	plugin.registerHTTPHandler(url.RestBridgeDomainKey(), GET, func() (interface{}, error) {
		return plugin.bdHandler.DumpBridgeDomains()
	})
	// GET FIB entries
	plugin.registerHTTPHandler(url.RestFibKey(), GET, func() (interface{}, error) {
		return plugin.fibHandler.DumpFIBTableEntries()
	})
	// GET cross connects
	plugin.registerHTTPHandler(url.RestXConnectKey(), GET, func() (interface{}, error) {
		return plugin.xcHandler.DumpXConnectPairs()
	})

	return nil
}

// registerHTTPHandler is common register method for all handlers
func (plugin *Plugin) registerHTTPHandler(key, method string, f func() (interface{}, error)) {
	handlerFunc := func(formatter *render.Render) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			res, err := f()
			if err != nil {
				plugin.Deps.Log.Errorf("Error: %v", err)
				w.Write([]byte("500 Internal server error: " + err.Error()))
				formatter.JSON(w, http.StatusInternalServerError, err)
				return
			}
			plugin.Deps.Log.Debug(res)
			formatter.JSON(w, http.StatusOK, res)
		}
	}
	plugin.HTTPHandlers.RegisterHTTPHandler(key, handlerFunc, method)
}

// staticRoutesGetHandler - used to get list of all static routes
func (plugin *Plugin) arpGetHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		plugin.Log.Debug("Getting list of all ARPs")

		// create an API channel
		ch, err := plugin.GoVppmux.NewAPIChannel()
		if err != nil {
			plugin.Log.Errorf("Error creating channel: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		defer ch.Close()

		l3Handler, err := l3plugin.NewArpVppHandler(ch, plugin.Log, nil)
		if err != nil {
			plugin.Log.Errorf("Error creating VPP handler: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		res, err := l3Handler.DumpArpEntries()
		if err != nil {
			plugin.Log.Errorf("Error: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, nil)
			return
		}

		plugin.Log.Debug(res)
		formatter.JSON(w, http.StatusOK, res)
	}
}

// staticRoutesGetHandler - used to get list of all static routes
func (plugin *Plugin) staticRoutesGetHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		plugin.Log.Debug("Getting list of all static routes")

		// create an API channel
		ch, err := plugin.GoVppmux.NewAPIChannel()
		if err != nil {
			plugin.Log.Errorf("Error creating channel: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		defer ch.Close()

		l3Handler, err := l3plugin.NewRouteVppHandler(ch, plugin.Log, nil)
		if err != nil {
			plugin.Log.Errorf("Error creating VPP handler: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		res, err := l3Handler.DumpStaticRoutes()
		if err != nil {
			plugin.Log.Errorf("Error: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, nil)
			return
		}

		plugin.Log.Debug(res)
		formatter.JSON(w, http.StatusOK, res)
	}
}

// interfaceACLGetHandler - used to get acl configuration for a particular interface
func (plugin *Plugin) interfaceACLGetHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		plugin.Log.Debug("Getting acl configuration of interface")

		vars := mux.Vars(req)
		if vars == nil {
			plugin.Log.Error("Interface software index not specified.")
			formatter.JSON(w, http.StatusNotFound, "Interface software index not specified.")
			return
		}

		plugin.Log.Infof("Received request for swIndex: %v", vars[swIndexVarName])

		swIndexuInt64, err := strconv.ParseUint(vars[swIndexVarName], 10, 32)
		if err != nil {
			plugin.Log.Error("Failed to unmarshal request body.")
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}

		swIndex := uint32(swIndexuInt64)
		if err != nil {
			plugin.Log.Errorf("Error creating VPP handler: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		res, err := plugin.aclHandler.DumpInterfaceIPAcls(swIndex)
		if err != nil {
			plugin.Deps.Log.Errorf("Error: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		res, err = plugin.aclHandler.DumpInterfaceMACIPAcls(swIndex)
		if err != nil {
			plugin.Log.Errorf("Error: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}

		plugin.Log.Debug(res)
		formatter.JSON(w, http.StatusOK, res)
	}
}

// exampleACLGetHandler - used to get an example ACL configuration
func (plugin *Plugin) exampleIpACLGetHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		plugin.Log.Debug("Getting example acl")

		ipRule := &acl.AccessLists_Acl_Rule_Match_IpRule{
			Ip: &acl.AccessLists_Acl_Rule_Match_IpRule_Ip{
				DestinationNetwork: "1.2.3.4/24",
				SourceNetwork:      "5.6.7.8/24",
			},
			Tcp: &acl.AccessLists_Acl_Rule_Match_IpRule_Tcp{
				DestinationPortRange: &acl.AccessLists_Acl_Rule_Match_IpRule_PortRange{
					LowerPort: 80,
					UpperPort: 8080,
				},
				SourcePortRange: &acl.AccessLists_Acl_Rule_Match_IpRule_PortRange{
					LowerPort: 10,
					UpperPort: 1010,
				},
				TcpFlagsMask:  0xFF,
				TcpFlagsValue: 9,
			},
		}

		rule := &acl.AccessLists_Acl_Rule{
			Match: &acl.AccessLists_Acl_Rule_Match{
				IpRule: ipRule,
			},
			AclAction: acl.AclAction_PERMIT,
		}

		aclRes := acl.AccessLists_Acl{
			AclName: "example",
			Rules:   []*acl.AccessLists_Acl_Rule{rule},
		}

		plugin.Log.Debug(aclRes)
		formatter.JSON(w, http.StatusOK, aclRes)
	}
}

func (plugin *Plugin) exampleMacIpACLGetHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		plugin.Deps.Log.Info("Getting example macip acl")

		macipRule := &acl.AccessLists_Acl_Rule_Match_MacIpRule{
			SourceAddress:        "192.168.0.1",
			SourceAddressPrefix:  uint32(16),
			SourceMacAddress:     "02:00:DE:AD:00:02",
			SourceMacAddressMask: "ff:ff:ff:ff:00:00",
		}

		rule := &acl.AccessLists_Acl_Rule{
			Match: &acl.AccessLists_Acl_Rule_Match{
				MacipRule: macipRule,
			},
			AclAction: acl.AclAction_PERMIT,
		}

		aclRes := acl.AccessLists_Acl{
			AclName: "example",
			Rules:   []*acl.AccessLists_Acl_Rule{rule},
		}

		plugin.Deps.Log.Debug(aclRes)
		formatter.JSON(w, http.StatusOK, aclRes)
	}
}

// ipACLPostHandler - used to get acl configuration for a particular interface
func (plugin *Plugin) ipACLPostHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			plugin.Deps.Log.Error("Failed to parse request body.")
			formatter.JSON(w, http.StatusBadRequest, err)
			return
		}
		aclParam := acl.AccessLists_Acl{}
		err = json.Unmarshal(body, &aclParam)
		if err != nil {
			plugin.Deps.Log.Error("Failed to unmarshal request body.")
			formatter.JSON(w, http.StatusBadRequest, err)
			return
		}

		// create an API channel
		ch, err := plugin.Deps.GoVppmux.NewAPIChannel()
		defer ch.Close()
		if err != nil {
			plugin.Deps.Log.Errorf("Error: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}

		var aclIndex struct {
			Idx uint32 `json:"acl_index"`
		}
		aclHandler, err := aclcalls.NewAclVppHandler(ch, ch, nil)
		if err != nil {
			plugin.Log.Errorf("Error creating VPP handler: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		aclIndex.Idx, err = aclHandler.AddIPAcl(aclParam.Rules, aclParam.AclName)
		if err != nil {
			plugin.Deps.Log.Errorf("Error: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, aclIndex)
			return
		}

		plugin.Deps.Log.Debug(aclIndex)
		formatter.JSON(w, http.StatusOK, aclIndex)
	}
}

func (plugin *Plugin) macipACLPostHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			plugin.Log.Error("Failed to parse request body.")
			formatter.JSON(w, http.StatusBadRequest, err)
			return
		}
		aclParam := acl.AccessLists_Acl{}
		err = json.Unmarshal(body, &aclParam)
		if err != nil {
			plugin.Log.Error("Failed to unmarshal request body.")
			formatter.JSON(w, http.StatusBadRequest, err)
			return
		}

		// create an API channel
		ch, err := plugin.GoVppmux.NewAPIChannel()
		if err != nil {
			plugin.Log.Errorf("Error creating channel: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		defer ch.Close()

		var aclIndex struct {
			Idx uint32 `json:"acl_index"`
		}
		aclHandler, err := aclcalls.NewAclVppHandler(ch, ch, nil)
		if err != nil {
			plugin.Log.Errorf("Error creating VPP handler: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		aclIndex.Idx, err = aclHandler.AddMacIPAcl(aclParam.Rules, aclParam.AclName)
		if err != nil {
			plugin.Log.Errorf("Error: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, aclIndex)
			return
		}

		plugin.Log.Debug(aclIndex)
		formatter.JSON(w, http.StatusOK, aclIndex)
	}
}

// commandHandler - used to execute VPP CLI commands
func (plugin *Plugin) commandHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			plugin.Log.Error("Failed to parse request body.")
			formatter.JSON(w, http.StatusBadRequest, err)
			return
		}

		var reqParam map[string]string
		err = json.Unmarshal(body, &reqParam)
		if err != nil {
			plugin.Log.Error("Failed to unmarshal request body.")
			formatter.JSON(w, http.StatusBadRequest, err)
			return
		}

		command, ok := reqParam["vppclicommand"]
		if !ok || command == "" {
			plugin.Log.Error("vppclicommand parameter missing or empty")
			formatter.JSON(w, http.StatusBadRequest, "vppclicommand parameter missing or empty")
			return
		}

		plugin.Log.Debugf("VPPCLI command: %v", command)

		ch, err := plugin.GoVppmux.NewAPIChannel()
		if err != nil {
			plugin.Log.Errorf("Error creating channel: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		defer ch.Close()

		r := &vpe.CliInband{
			Length: uint32(len(command)),
			Cmd:    []byte(command),
		}
		reply := &vpe.CliInbandReply{}
		err = ch.SendRequest(r).ReceiveReply(reply)
		if err != nil {
			err = fmt.Errorf("Sending request failed: %v", err)
			plugin.Log.Error(err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		} else if reply.Retval > 0 {
			err = fmt.Errorf("Request returned error code: %v", reply.Retval)
			plugin.Log.Error(err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}

		plugin.Log.Debugf("VPPCLI response: %s", reply.Reply)
		formatter.Text(w, http.StatusOK, string(reply.Reply))
	}
}

func (plugin *Plugin) sendCommand(ch govppapi.Channel, command string) ([]byte, error) {
	r := &vpe.CliInband{
		Length: uint32(len(command)),
		Cmd:    []byte(command),
	}

	reply := &vpe.CliInbandReply{}
	if err := ch.SendRequest(r).ReceiveReply(reply); err != nil {
		return nil, fmt.Errorf("Sending request failed: %v", err)
	} else if reply.Retval > 0 {
		return nil, fmt.Errorf("Request returned error code: %v", reply.Retval)
	}

	return reply.Reply[:reply.Length], nil
}

// telemetryHandler - returns various telemetry data
func (plugin *Plugin) telemetryHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		ch, err := plugin.GoVppmux.NewAPIChannel()
		if err != nil {
			plugin.Log.Errorf("Error creating channel: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		defer ch.Close()

		type cmdOut struct {
			Command string
			Output  interface{}
		}
		var cmdOuts []cmdOut

		var runCmd = func(command string) {
			out, err := plugin.sendCommand(ch, command)
			if err != nil {
				plugin.Log.Errorf("Sending command failed: %v", err)
				formatter.JSON(w, http.StatusInternalServerError, err)
				return
			}
			cmdOuts = append(cmdOuts, cmdOut{
				Command: command,
				Output:  string(out),
			})
		}

		runCmd("show node counters")
		runCmd("show runtime")
		runCmd("show buffers")
		runCmd("show memory")
		runCmd("show ip fib")
		runCmd("show ip6 fib")

		formatter.JSON(w, http.StatusOK, cmdOuts)
	}
}

// telemetryMemoryHandler - returns various telemetry data
func (plugin *Plugin) telemetryMemoryHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		ch, err := plugin.GoVppmux.NewAPIChannel()
		if err != nil {
			plugin.Log.Errorf("Error creating channel: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		defer ch.Close()

		info, err := vppcalls.GetMemory(ch)
		if err != nil {
			plugin.Log.Errorf("Sending command failed: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}

		formatter.JSON(w, http.StatusOK, info)
	}
}

// telemetryHandler - returns various telemetry data
func (plugin *Plugin) telemetryRuntimeHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		ch, err := plugin.GoVppmux.NewAPIChannel()
		if err != nil {
			plugin.Log.Errorf("Error creating channel: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		defer ch.Close()

		runtimeInfo, err := vppcalls.GetRuntimeInfo(ch)
		if err != nil {
			plugin.Log.Errorf("Sending command failed: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}

		formatter.JSON(w, http.StatusOK, runtimeInfo)
	}
}

// telemetryHandler - returns various telemetry data
func (plugin *Plugin) telemetryNodeCountHandler(formatter *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		ch, err := plugin.GoVppmux.NewAPIChannel()
		if err != nil {
			plugin.Log.Errorf("Error creating channel: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}
		defer ch.Close()

		nodeCounters, err := vppcalls.GetNodeCounters(ch)
		if err != nil {
			plugin.Log.Errorf("Sending command failed: %v", err)
			formatter.JSON(w, http.StatusInternalServerError, err)
			return
		}

		formatter.JSON(w, http.StatusOK, nodeCounters)
	}
}

// indexHandler - used to get index page
func (plugin *Plugin) indexHandler(formatter *render.Render) http.HandlerFunc {
	r := render.New(render.Options{
		Directory:  "templates",
		Asset:      Asset,
		AssetNames: AssetNames,
	})
	return func(w http.ResponseWriter, req *http.Request) {
		plugin.Log.Debugf("%v - %s %q", req.RemoteAddr, req.Method, req.URL)

		r.HTML(w, http.StatusOK, "index", plugin.indexItems)
	}
}
