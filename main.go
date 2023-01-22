package main

import (
	"flag"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/logger"
	"github.com/rs/tzsp"
)

var (
	device       string        = "veth0"
	snapshot_len int32         = 1024
	promiscuous  bool          = false
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	relayconn    *net.UDPConn
	snaplen      int32 = 1600
)

// sudo ip link add veth0 type veth peer name veth1
// sudo ip link set veth0 up
// sudo ip link set veth1 up
// sudo ip link set dev veth0 mtu 9000
// sudo ip link set dev veth1 mtu 9000

func main() {
	var lPort = flag.Int("p", 37008, "Listening port")
	var dPort = flag.String("dp", "37008", "Target port")
	var dIP = flag.String("ip", "192.168.0.1", "Target IP")
	var netInt = flag.String("I", "eth0", "Interface to capture")
	var forward = flag.Bool("f", false, "Forward tzsp traffic to the target ip")

	flag.Parse()

	// Listen for tzsp traffic
	addr := net.UDPAddr{
		Port: *lPort,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatal(err)
	}

	// Relay to destination

	udpAddr, err := net.ResolveUDPAddr("udp4", *dIP+":"+*dPort)
	checkError(err)

	relayconn, err = net.DialUDP("udp", nil, udpAddr)
	checkError(err)

	buf := make([]byte, 65535)

	// Copy traffic on veth0 interface

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if *forward {
		go func() {
			// Capture traffic
			handlecap, err := pcap.OpenLive(*netInt, snaplen, true, pcap.BlockForever)
			checkError(err)
			exclude := " and (not (dst port " + strconv.Itoa(*lPort) + " and dst host " + *dIP + " ))"
			err = handlecap.SetBPFFilter("port " + strconv.Itoa(*lPort) + exclude)
			checkError(err)
			packetSource := gopacket.NewPacketSource(handlecap, handle.LinkType())

			for packet := range packetSource.Packets() {
				handlePacket(packet)
			}
		}()
	}

	for {
		l, _, err := conn.ReadFrom(buf)
		if err != nil {
			panic(err)
		}
		p, err := tzsp.Parse(buf[:l])
		if err != nil {
			panic(err)
		}
		err = handle.WritePacketData(p.Data)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func handlePacket(p gopacket.Packet) {
	udpLayer := p.TransportLayer()
	if udpLayer != nil {
		relayconn.Write(udpLayer.LayerPayload())
		// We don't check for error here.
		// The endpoint might not be listening yet.
	}
	if err := p.ErrorLayer(); err != nil {
		logger.Info(2, "Error decoding some part of the packet.")
	}
}

func checkError(err error) {
	if err != nil {
		logger.Error(3, err.Error())
		panic(err.Error())
	}
}
