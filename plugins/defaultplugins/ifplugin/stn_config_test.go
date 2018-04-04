// Copyright (c) 2018 Cisco and/or its affiliates.
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

package ifplugin_test

import (
	"net"
	"testing"

	"git.fd.io/govpp.git/adapter/mock"
	"git.fd.io/govpp.git/core"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/vpp-agent/idxvpp/nametoidx"
	stn_api "github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/stn"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/bin_api/vpe"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/stn"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/tests/vppcallmock"
	. "github.com/onsi/gomega"
)

/* STN configurator init and close */

// Test init function
func TestStnConfiguratorInit(t *testing.T) {
	RegisterTestingT(t)
	connection, _ := core.Connect(&mock.VppAdapter{})
	defer connection.Disconnect()

	plugin := &ifplugin.StnConfigurator{}
	err := plugin.Init("test-plugin-name", logging.ForPlugin("test-log", logrus.NewLogRegistry()), connection,
		nil, true)
	Expect(err).To(BeNil())

	err = plugin.Close()
	Expect(err).To(BeNil())
}

/* STN Test Cases */

// Add STN rule
func TestStnConfiguratorAddRule(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	data := getTestStnRule("rule1", "if1", "10.0.0.1")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test add stn rule
	err = plugin.Add(data)
	Expect(err).To(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeTrue())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Add STN rule with full IP (address/mask)
func TestStnConfiguratorAddRuleFullIP(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	data := getTestStnRule("rule1", "if1", "10.0.0.1/24")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test add stn rule with full IP
	err = plugin.Add(data)
	Expect(err).To(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeTrue())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Add STN rule while interface is missing
func TestStnConfiguratorAddRuleMissingInterface(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, _ := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	data := getTestStnRule("rule1", "if1", "10.0.0.1")
	// Test add rule while interface is not registered
	err = plugin.Add(data)
	Expect(err).To(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeTrue())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeTrue())
}

// Add STN rule while non-zero return value is get
func TestStnConfiguratorAddRuleRetvalError(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{
		Retval: 1,
	})
	// Data
	data := getTestStnRule("rule1", "if1", "10.0.0.1")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test add rule returns -1
	err = plugin.Add(data)
	Expect(err).ToNot(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Add nil STN rule
func TestStnConfiguratorAddRuleNoInput(t *testing.T) {
	var err error
	// Setup
	_, conn, plugin, _ := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Test add empty rule
	err = plugin.Add(nil)
	Expect(err).ToNot(BeNil())
}

// Add STN rule without interface
func TestStnConfiguratorAddRuleNoInterface(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	data := getTestStnRule("rule1", "", "10.0.0.1")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test add rule with invalid interface data
	err = plugin.Add(data)
	Expect(err).ToNot(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Add STN rule without IP
func TestStnConfiguratorAddRuleNoIP(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	data := getTestStnRule("rule1", "if1", "")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test add rule with missing IP data
	err = plugin.Add(data)
	Expect(err).ToNot(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Add STN rule with invalid IP
func TestStnConfiguratorAddRuleInvalidIP(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	data := getTestStnRule("rule1", "if1", "no-ip")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test add rule with invalid IP data
	err = plugin.Add(data)
	Expect(err).ToNot(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Delete STN rule
func TestStnConfiguratorDeleteRule(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	data := getTestStnRule("rule1", "if1", "10.0.0.1")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test delete stn rule
	err = plugin.Add(data)
	Expect(err).To(BeNil())
	err = plugin.Delete(data)
	Expect(err).To(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Delete STN rule with missing interface
func TestStnConfiguratorDeleteRuleMissingInterface(t *testing.T) {
	var err error
	// Setup
	_, conn, plugin, _ := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Data
	data := getTestStnRule("rule1", "if1", "10.0.0.1")
	// Test delete rule while interface is not registered
	err = plugin.Add(data)
	Expect(err).To(BeNil())
	err = plugin.Delete(data)
	Expect(err).To(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Delete STN rule non-zero return value
func TestStnConfiguratorDeleteRuleRetvalError(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{
		Retval: 1,
	})
	// Data
	data := getTestStnRule("rule1", "if1", "10.0.0.1")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test delete rule with return value -1
	err = plugin.Add(data)
	Expect(err).To(BeNil())
	err = plugin.Delete(data)
	Expect(err).ToNot(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Delete STN rule failed check
func TestStnConfiguratorDeleteRuleCheckError(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	data := getTestStnRule("rule1", "if1", "no-ip")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	err = plugin.Add(data)
	Expect(err).ToNot(BeNil())
	// Test delete rule with error check
	err = plugin.Delete(data)
	Expect(err).ToNot(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Delete STN rule without interface
func TestStnConfiguratorDeleteRuleNoInterface(t *testing.T) {
	var err error
	// Setup
	_, conn, plugin, _ := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Data
	data := getTestStnRule("rule1", "", "10.0.0.1")
	// Test delete rule
	err = plugin.Delete(data)
	Expect(err).ToNot(BeNil())
}

// Modify STN rule
func TestStnConfiguratorModifyRule(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	oldData := getTestStnRule("rule1", "if1", "10.0.0.1")
	newData := getTestStnRule("rule1", "if1", "10.0.0.2")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test modify rule
	err = plugin.Add(oldData)
	Expect(err).To(BeNil())
	err = plugin.Modify(oldData, newData)
	Expect(err).To(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeTrue())
}

// Modify STN rule nil check
func TestStnConfiguratorModifyRuleNilCheck(t *testing.T) {
	var err error
	// Setup
	_, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Data
	oldData := getTestStnRule("rule1", "if1", "10.0.0.1")
	newData := getTestStnRule("rule1", "if1", "10.0.0.2")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test nil old rule
	err = plugin.Modify(nil, newData)
	Expect(err).ToNot(BeNil())
	// Test nil new rule
	err = plugin.Modify(oldData, nil)
	Expect(err).ToNot(BeNil())
}

// Dump STN rule
func TestStnConfiguratorDumpRule(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnRuleDetails{
		IsIP4:     1,
		IPAddress: net.ParseIP("10.0.0.1"),
		SwIfIndex: 1,
	})
	ctx.MockVpp.MockReply(&vpe.ControlPingReply{})
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test rule dump
	data, err := plugin.Dump()
	Expect(err).To(BeNil())
	Expect(data).ToNot(BeNil())
	Expect(data).To(HaveLen(1))
	Expect(data[0].SwIfIndex).To(BeEquivalentTo(1))
	Expect(data[0].IPAddress).To(BeEquivalentTo(net.ParseIP("10.0.0.1")))
	Expect(data[0].IsIP4).To(BeEquivalentTo(1))
}

// Resolve new interface for STN
func TestStnConfiguratorResolveCreatedInterface(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	data := getTestStnRule("rule1", "if1", "10.0.0.1")
	// Test add rule while interface is not registered
	err = plugin.Add(data)
	Expect(err).To(BeNil())
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeTrue())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeTrue())
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	// Test resolving of new interface
	plugin.ResolveCreatedInterface("if1")
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeTrue())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

// Resolve removed interface for STN
func TestStnConfiguratorResolveDeletedInterface(t *testing.T) {
	var err error
	// Setup
	ctx, conn, plugin, swIfIndices := stnTestSetup(t)
	defer stnTestTeardown(conn, plugin)
	// Reply set
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	ctx.MockVpp.MockReply(&stn_api.StnAddDelRuleReply{})
	// Data
	data := getTestStnRule("rule1", "if1", "10.0.0.1")
	// Register
	swIfIndices.RegisterName("if1", 1, nil)
	err = plugin.Add(data)
	Expect(err).To(BeNil())
	// Test resolving of deleted interface
	swIfIndices.UnregisterName("if1")
	plugin.ResolveDeletedInterface("if1")
	Expect(plugin.IndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
	Expect(plugin.UnstoredIndexExistsFor(ifplugin.StnIdentifier("if1"))).To(BeFalse())
}

/* STN Test Setup */

func stnTestSetup(t *testing.T) (*vppcallmock.TestCtx, *core.Connection, *ifplugin.StnConfigurator, ifaceidx.SwIfIndexRW) {
	RegisterTestingT(t)
	ctx := &vppcallmock.TestCtx{
		MockVpp: &mock.VppAdapter{},
	}
	connection, err := core.Connect(ctx.MockVpp)
	Expect(err).ShouldNot(HaveOccurred())
	// Logger
	log := logging.ForPlugin("test-log", logrus.NewLogRegistry())
	log.SetLevel(logging.DebugLevel)
	// Interface indices
	swIfIndices := ifaceidx.NewSwIfIndex(nametoidx.NewNameToIdx(log, "stn-configurator-test", "stn", nil))
	// Configurator
	plugin := &ifplugin.StnConfigurator{}
	err = plugin.Init("test-stn", log, connection, swIfIndices, false)
	Expect(err).To(BeNil())

	return ctx, connection, plugin, swIfIndices
}

func stnTestTeardown(connection *core.Connection, plugin *ifplugin.StnConfigurator) {
	connection.Disconnect()
	err := plugin.Close()
	Expect(err).To(BeNil())
}

/* STN Test Data */

func getTestStnRule(name, ifName, ip string) *stn.StnRule {
	return &stn.StnRule{
		RuleName:  name,
		Interface: ifName,
		IpAddress: ip,
	}
}
