Install

gem install packetfu
gem install pcaprub

type "ruby sniffDNS.rb --targetsAddr <targets IP Address> --iface <interface> --spoofAddr <spoof IP Address>"

Default configuration variables if the arguments are not specified
   •  iface = wlan0
   •  targetsAddr = 192.168.0.33
   •  spoofAddr = 24.86.113.108

sniffDNS.rb DNS Sniffing and Sending Program
arpSpoof.rb Arpspoofing