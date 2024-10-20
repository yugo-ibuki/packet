package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// 利用可能なネットワークインターフェースを取得
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// 利用可能なインターフェースを表示
	fmt.Println("Available network interfaces:")
	for i, device := range devices {
		fmt.Printf("%d. %s\n", i+1, device.Name)
	}

	// ユーザーにインターフェースを選択してもらう
	var selectedIndex int
	fmt.Print("Select an interface (enter the number): ")
	_, err = fmt.Scanf("%d", &selectedIndex)
	if err != nil || selectedIndex < 1 || selectedIndex > len(devices) {
		log.Fatal("Invalid selection")
	}

	interfaceName := devices[selectedIndex-1].Name
	fmt.Printf("Selected interface: %s\n", interfaceName)

	// パケットキャプチャを開始
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Error opening device:", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// パケットの基本情報を表示
		fmt.Println("Time:", time.Now())
		fmt.Println("Length:", packet.Metadata().Length)

		// NetworkLayerが存在するか確認
		if networkLayer := packet.NetworkLayer(); networkLayer != nil {
			fmt.Println("Protocol:", networkLayer.LayerType())
		} else {
			fmt.Println("Protocol: Unknown")
		}

		// 送信元と宛先のIPアドレスを表示（存在する場合）
		//if ipLayer := packet.Layer(gopacket.LayerTypeIPv4); ipLayer != nil {
		//	ip, _ := ipLayer.(*gopacket.IPv4)
		//	fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		//}

		fmt.Println("------")
	}
}
