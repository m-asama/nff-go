// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var (
	l3Rules *packet.L3Rules
	outport uint
	inport  uint
)

// Main function for constructing packet processing graph.
func main() {
	var err error
	flag.UintVar(&outport, "outport", 1, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.Parse()

	// Initialize NFF-GO library at 8 cores by default
	config := flow.Config{
		CPUList: "0-7",
	}
	flow.CheckFatal(flow.SystemInit(&config))

	// Get filtering rules from access control file.
	l3Rules, err = packet.GetL3ACLFromORIG("Firewall.conf")
	flow.CheckFatal(err)

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow, err := flow.SetReceiver(uint8(inport))
	flow.CheckFatal(err)

	// Separate packet flow based on ACL.
	rejectFlow, err := flow.SetSeparator(inputFlow, l3Separator, nil)
	flow.CheckFatal(err)

	// Drop rejected packets.
	flow.CheckFatal(flow.SetStopper(rejectFlow))

	// Send accepted packets to first port. Send queue will be added automatically.
	flow.CheckFatal(flow.SetSender(inputFlow, uint8(outport)))

	// Begin to process packets.
	flow.CheckFatal(flow.SystemStart())
}

// User defined function for separating packets
func l3Separator(currentPacket *packet.Packet, context flow.UserContext) bool {
	// Return whether packet is accepted or not. Based on ACL rules.
	return currentPacket.L3ACLPermit(l3Rules)
}
