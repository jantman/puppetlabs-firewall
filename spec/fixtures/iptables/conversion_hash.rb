# These hashes allow us to iterate across a series of test data
# creating rspec examples for each parameter to ensure the input :line
# extrapolates to the desired value for the parameter in question. And
# vice-versa

# This hash is for testing a line conversion to a hash of parameters
# which will be used to create a resource.
ARGS_TO_HASH = {
  'dport_and_sport' => {
    :line => '-A nova-compute-FORWARD -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp --sport 68 --dport 67 -j ACCEPT',
    :table => 'filter',
    :params => {
      :action => 'accept',
      :chain => 'nova-compute-FORWARD',
      :source => '0.0.0.0/32',
      :destination => '255.255.255.255/32',
      :sport => ['68'],
      :dport => ['67'],
      :proto => 'udp',
    },
  },
  'long_rule_1' => {
    :line => '-A INPUT -s 1.1.1.1/32 -d 1.1.1.1/32 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -m comment --comment "000 allow foo" -j ACCEPT',
    :table => 'filter',
    :compare_all => true,
    :params => {
      :action => "accept",
      :chain => "INPUT",
      :destination => "1.1.1.1/32",
      :dport => ["7061","7062"],
      :ensure => :present,
      :line => '-A INPUT -s 1.1.1.1/32 -d 1.1.1.1/32 -p tcp -m multiport --dports 7061,7062 -m multiport --sports 7061,7062 -m comment --comment "000 allow foo" -j ACCEPT',
      :name => "allow foo",
      :order => 0,
      :proto => "tcp",
      :provider => "iptables",
      :source => "1.1.1.1/32",
      :sport => ["7061","7062"],
      :table => "filter",
    },
  },
  'action_drop_1' => {
    :line => '-A INPUT -m comment --comment "000 allow foo" -j DROP',
    :table => 'filter',
    :params => {
      :jump => nil,
      :action => "drop",
    },
  },
  'action_reject_1' => {
    :line => '-A INPUT -m comment --comment "000 allow foo" -j REJECT',
    :table => 'filter',
    :params => {
      :jump => nil,
      :action => "reject",
    },
  },
  'action_nil_1' => {
    :line => '-A INPUT -m comment --comment "000 allow foo"',
    :table => 'filter',
    :params => {
      :jump => nil,
      :action => nil,
    },
  },
  'jump_custom_chain_1' => {
    :line => '-A INPUT -m comment --comment "000 allow foo" -j custom_chain',
    :table => 'filter',
    :params => {
      :jump => "custom_chain",
      :action => nil,
    },
  },
  'source_destination_ipv4_no_cidr' => {
    :line => '-A INPUT -s 1.1.1.1 -d 2.2.2.2 -m comment --comment "000 source destination ipv4 no cidr"',
    :table => 'filter',
    :params => {
      :source => '1.1.1.1/32',
      :destination => '2.2.2.2/32',
    },
  },
  'source_destination_ipv6_no_cidr' => {
    :line => '-A INPUT -s 2001:db8:85a3::8a2e:370:7334 -d 2001:db8:85a3::8a2e:370:7334 -m comment --comment "000 source destination ipv6 no cidr"',
    :table => 'filter',
    :params => {
      :source => '2001:db8:85a3::8a2e:370:7334/128',
      :destination => '2001:db8:85a3::8a2e:370:7334/128',
    },
  },
  'source_destination_ipv4_netmask' => {
    :line => '-A INPUT -s 1.1.1.0/255.255.255.0 -d 2.2.0.0/255.255.0.0 -m comment --comment "000 source destination ipv4 netmask"',
    :table => 'filter',
    :params => {
      :source => '1.1.1.0/24',
      :destination => '2.2.0.0/16',
    },
  },
  'source_destination_ipv6_netmask' => {
    :line => '-A INPUT -s 2001:db8:1234::/ffff:ffff:ffff:0000:0000:0000:0000:0000 -d 2001:db8:4321::/ffff:ffff:ffff:0000:0000:0000:0000:0000 -m comment --comment "000 source destination ipv6 netmask"',
    :table => 'filter',
    :params => {
      :source => '2001:db8:1234::/48',
      :destination => '2001:db8:4321::/48',
    },
  },
  'source_destination_negate_source' => {
    :line => '-A INPUT ! -s 1.1.1.1 -d 2.2.2.2 -m comment --comment "000 negated source address"',
    :table => 'filter',
    :params => {
      :source => '! 1.1.1.1/32',
      :destination => '2.2.2.2/32',
    },
  },
  'source_destination_negate_destination' => {
    :line => '-A INPUT -s 1.1.1.1 ! -d 2.2.2.2 -m comment --comment "000 negated destination address"',
    :table => 'filter',
    :params => {
      :source => '1.1.1.1/32',
      :destination => '! 2.2.2.2/32',
    },
  },
  'source_destination_negate_destination_alternative' => {
    :line => '-A INPUT -s 1.1.1.1 -d ! 2.2.2.2 -m comment --comment "000 negated destination address alternative"',
    :table => 'filter',
    :params => {
      :source => '1.1.1.1/32',
      :destination => '! 2.2.2.2/32',
    },
  },
  'dport_range_1' => {
    :line => '-A INPUT -m multiport --dports 1:1024 -m comment --comment "000 allow foo"',
    :table => 'filter',
    :params => {
      :dport => ["1-1024"],
    },
  },
  'dport_range_2' => {
    :line => '-A INPUT -m multiport --dports 15,512:1024 -m comment --comment "000 allow foo"',
    :table => 'filter',
    :params => {
      :dport => ["15","512-1024"],
    },
  },
  'sport_range_1' => {
    :line => '-A INPUT -m multiport --sports 1:1024 -m comment --comment "000 allow foo"',
    :table => 'filter',
    :params => {
      :sport => ["1-1024"],
    },
  },
  'sport_range_2' => {
    :line => '-A INPUT -m multiport --sports 15,512:1024 -m comment --comment "000 allow foo"',
    :table => 'filter',
    :params => {
      :sport => ["15","512-1024"],
    },
  },
  'dst_type_1' => {
    :line => '-A INPUT -m addrtype --dst-type LOCAL',
    :table => 'filter',
    :params => {
      :dst_type => 'LOCAL',
    },
  },
  'src_type_1' => {
    :line => '-A INPUT -m addrtype --src-type LOCAL',
    :table => 'filter',
    :params => {
      :src_type => 'LOCAL',
    },
  },
  'dst_range_1' => {
    :line => '-A INPUT -m iprange --dst-range 10.0.0.2-10.0.0.20',
    :table => 'filter',
    :params => {
      :dst_range => '10.0.0.2-10.0.0.20',
    },
  },
  'src_range_1' => {
    :line => '-A INPUT -m iprange --src-range 10.0.0.2-10.0.0.20',
    :table => 'filter',
    :params => {
      :src_range => '10.0.0.2-10.0.0.20',
    },
  },
  'tcp_flags_1' => {
    :line => '-A INPUT -p tcp -m tcp --tcp-flags SYN,RST,ACK,FIN SYN -m comment --comment "000 initiation"',
    :table => 'filter',
    :compare_all => true,
    :chain => 'INPUT',
    :proto => 'tcp',
    :params => {
      :chain => "INPUT",
      :ensure => :present,
      :line => '-A INPUT -p tcp -m tcp --tcp-flags SYN,RST,ACK,FIN SYN -m comment --comment "000 initiation"',
      :name => "initiation",
      :order => 0,
      :proto => "tcp",
      :provider => "iptables",
      :table => "filter",
      :tcp_flags => "SYN,RST,ACK,FIN SYN",
    },
  },
  'state_returns_sorted_values' => {
    :line => '-A INPUT -m state --state INVALID,RELATED,ESTABLISHED',
    :table => 'filter',
    :params => {
      :state => ['ESTABLISHED', 'INVALID', 'RELATED'],
      :action => nil,
    },
  },
  'ctstate_returns_sorted_values' => {
    :line => '-A INPUT -m conntrack --ctstate INVALID,RELATED,ESTABLISHED',
    :table => 'filter',
    :params => {
      :ctstate => ['ESTABLISHED', 'INVALID', 'RELATED'],
      :action => nil,
    },
  },
  'comment_string_character_validation' => {
    :line => '-A INPUT -s 192.168.0.1/32 -m comment --comment "000 allow from 192.168.0.1, please"',
    :table => 'filter',
    :params => {
      :source => '192.168.0.1/32',
    },
  },
  'log_level_debug' => {
    :line => '-A INPUT -m comment --comment "956 INPUT log-level" -m state --state NEW -j LOG --log-level 7',
    :table => 'filter',
    :params => {
      :state => ['NEW'],
      :log_level => '7',
      :jump => 'LOG'
    },
  },
  'log_level_warn' => {
    :line => '-A INPUT -m comment --comment "956 INPUT log-level" -m state --state NEW -j LOG',
    :table => 'filter',
    :params => {
      :state => ['NEW'],
      :log_level => '4',
      :jump => 'LOG'
    },
  },
  'load_limit_module_and_implicit_burst' => {
    :line => '-A INPUT -m multiport --dports 123 -m comment --comment "057 INPUT limit NTP" -m limit --limit 15/hour',
    :table => 'filter',
    :params => {
      :dport => ['123'],
      :limit => '15/hour',
      :burst => '5'
    },
  },
  'limit_with_explicit_burst' => {
    :line => '-A INPUT -m multiport --dports 123 -m comment --comment "057 INPUT limit NTP" -m limit --limit 30/hour --limit-burst 10',
    :table => 'filter',
    :params => {
      :dport => ['123'],
      :limit => '30/hour',
      :burst => '10'
    },
  },
  'proto_ipencap' => {
    :line => '-A INPUT -p ipencap -m comment --comment "0100 INPUT accept ipencap"',
    :table => 'filter',
    :params => {
      :proto => 'ipencap',
    }
  },
  'load_uid_owner_filter_module' => {
    :line => '-A OUTPUT -m owner --uid-owner root -m comment --comment "057 OUTPUT uid root only" -j ACCEPT',
    :table => 'filter',
    :params => {
      :action => 'accept',
      :uid => 'root',
      :chain => 'OUTPUT',
    },
  },
  'load_uid_owner_postrouting_module' => {
    :line => '-t mangle -A POSTROUTING -m owner --uid-owner root -m comment --comment "057 POSTROUTING uid root only" -j ACCEPT',
    :table => 'mangle',
    :params => {
      :action => 'accept',
      :chain => 'POSTROUTING',
      :uid => 'root',
    },
  },
  'load_gid_owner_filter_module' => {
    :line => '-A OUTPUT -m owner --gid-owner root -m comment --comment "057 OUTPUT gid root only" -j ACCEPT',
    :table => 'filter',
    :params => {
      :action => 'accept',
      :chain => 'OUTPUT',
      :gid => 'root',
    },
  },
  'load_gid_owner_postrouting_module' => {
    :line => '-t mangle -A POSTROUTING -m owner --gid-owner root -m comment --comment "057 POSTROUTING gid root only" -j ACCEPT',
    :table => 'mangle',
    :params => {
      :action => 'accept',
      :chain => 'POSTROUTING',
      :gid => 'root',
    },
  },
  'mark_set-mark' => {
    :line => '-t mangle -A PREROUTING -j MARK --set-xmark 0x3e8/0xffffffff',
    :table => 'mangle',
    :params => {
      :jump     => 'MARK',
      :chain    => 'PREROUTING',
      :set_mark => '0x3e8/0xffffffff',
    }
  },
  'iniface_1' => {
    :line => '-A INPUT -i eth0 -m comment --comment "060 iniface" -j DROP',
    :table => 'filter',
    :params => {
      :action => 'drop',
      :chain => 'INPUT',
      :iniface => 'eth0',
    },
  },
  'iniface_with_vlans_1' => {
    :line => '-A INPUT -i eth0.234 -m comment --comment "060 iniface" -j DROP',
    :table => 'filter',
    :params => {
      :action => 'drop',
      :chain => 'INPUT',
      :iniface => 'eth0.234',
    },
  },
  'iniface_with_plus_1' => {
    :line => '-A INPUT -i eth+ -m comment --comment "060 iniface" -j DROP',
    :table => 'filter',
    :params => {
      :action => 'drop',
      :chain => 'INPUT',
      :iniface => 'eth+',
    },
  },
  'outiface_1' => {
    :line => '-A OUTPUT -o eth0 -m comment --comment "060 outiface" -j DROP',
    :table => 'filter',
    :params => {
      :action => 'drop',
      :chain => 'OUTPUT',
      :outiface => 'eth0',
    },
  },
  'outiface_with_vlans_1' => {
    :line => '-A OUTPUT -o eth0.234 -m comment --comment "060 outiface" -j DROP',
    :table => 'filter',
    :params => {
      :action => 'drop',
      :chain => 'OUTPUT',
      :outiface => 'eth0.234',
    },
  },
  'outiface_with_plus_1' => {
    :line => '-A OUTPUT -o eth+ -m comment --comment "060 outiface" -j DROP',
    :table => 'filter',
    :params => {
      :action => 'drop',
      :chain => 'OUTPUT',
      :outiface => 'eth+',
    },
  },
  'pkttype multicast' => {
    :line => '-A INPUT -m pkttype --pkt-type multicast -j ACCEPT',
    :table => 'filter',
    :params => {
      :action => 'accept',
      :pkttype => 'multicast',
    },
  },
  'socket_option' => {
    :line => '-A PREROUTING -m socket -j ACCEPT',
    :table => 'mangle',
    :params => {
      :action => 'accept',
      :chain => 'PREROUTING',
      :socket => true,
    },
  },
  'isfragment_option' => {
    :line => '-A INPUT -f -m comment --comment "010 a-f comment with dashf" -j ACCEPT',
    :table => 'filter',
    :params => {
      :name => 'a-f comment with dashf',
      :order => 10,
      :action => 'accept',
      :isfragment => true,
    },
  },
  'single_tcp_sport' => {
    :line => '-A OUTPUT -s 10.94.100.46/32 -p tcp -m tcp --sport 20443 -j ACCEPT',
    :table => 'mangle',
    :params => {
      :action => 'accept',
      :chain => 'OUTPUT',
      :source => "10.94.100.46/32",
      :proto => "tcp",
      :sport => ["20443"],
    },
  },
  'single_udp_sport' => {
    :line => '-A OUTPUT -s 10.94.100.46/32 -p udp -m udp --sport 20443 -j ACCEPT',
    :table => 'mangle',
    :params => {
      :action => 'accept',
      :chain => 'OUTPUT',
      :source => "10.94.100.46/32",
      :proto => "udp",
      :sport => ["20443"],
    },
  },
  'single_tcp_dport' => {
    :line => '-A OUTPUT -s 10.94.100.46/32 -p tcp -m tcp --dport 20443 -j ACCEPT',
    :table => 'mangle',
    :params => {
      :action => 'accept',
      :chain => 'OUTPUT',
      :source => "10.94.100.46/32",
      :proto => "tcp",
      :dport => ["20443"],
    },
  },
  'single_udp_dport' => {
    :line => '-A OUTPUT -s 10.94.100.46/32 -p udp -m udp --dport 20443 -j ACCEPT',
    :table => 'mangle',
    :params => {
      :action => 'accept',
      :chain => 'OUTPUT',
      :source => "10.94.100.46/32",
      :proto => "udp",
      :dport => ["20443"],
    },
  },
}

# This hash is for testing converting a hash to an argument line.
HASH_TO_ARGS = {
  'long_rule_1' => {
    :params => {
      :action => "accept",
      :chain => "INPUT",
      :destination => "1.1.1.1",
      :dport => ["7061","7062"],
      :ensure => :present,
      :name => "allow foo",
      :order => 0,
      :proto => "tcp",
      :source => "1.1.1.1",
      :sport => ["7061","7062"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-s", "1.1.1.1/32", "-d", "1.1.1.1/32", "-p", :tcp, "-m", "multiport", "--sports", "7061,7062", "-m", "multiport", "--dports", "7061,7062", "-m", "comment", "--comment", "000 allow foo", "-j", "ACCEPT"],
  },
  'long_rule_2' => {
    :params => {
      :chain => "INPUT",
      :destination => "2.10.13.3/24",
      :dport => ["7061"],
      :ensure => :present,
      :jump => "my_custom_chain",
      :name => "allow bar",
      :order => 700,
      :proto => "udp",
      :source => "1.1.1.1",
      :sport => ["7061","7062"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-s", "1.1.1.1/32", "-d", "2.10.13.0/24", "-p", :udp, "-m", "multiport", "--sports", "7061,7062", "-m", "multiport", "--dports", "7061", "-m", "comment", "--comment", "700 allow bar", "-j", "my_custom_chain"],
  },
  'no_action' => {
    :params => {
      :name => "no action",
      :order => 100,
      :table => "filter",
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "comment", "--comment",
      "100 no action"],
  },
  'zero_prefixlen_ipv4' => {
    :params => {
      :name => 'zero prefix length ipv4',
      :order => 100,
      :table => 'filter',
      :source => '0.0.0.0/0',
      :destination => '0.0.0.0/0',
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'comment', '--comment', '100 zero prefix length ipv4'],
  },
  'zero_prefixlen_ipv6' => {
    :params => {
      :name => 'zero prefix length ipv6',
      :order => 100,
      :table => 'filter',
      :source => '::/0',
      :destination => '::/0',
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'comment', '--comment', '100 zero prefix length ipv6'],
  },
  'source_destination_ipv4_no_cidr' => {
    :params => {
      :name => 'source destination ipv4 no cidr',
      :order => 100,
      :table => 'filter',
      :source => '1.1.1.1',
      :destination => '2.2.2.2',
    },
    :args => ['-t', :filter, '-s', '1.1.1.1/32', '-d', '2.2.2.2/32', '-p', :tcp, '-m', 'comment', '--comment', '000 source destination ipv4 no cidr'],
  },
 'source_destination_ipv6_no_cidr' => {
    :params => {
      :name => 'source destination ipv6 no cidr',
      :order => 0,
      :table => 'filter',
      :source => '2001:db8:1234::',
      :destination => '2001:db8:4321::',
    },
    :args => ['-t', :filter, '-s', '2001:db8:1234::/128', '-d', '2001:db8:4321::/128', '-p', :tcp, '-m', 'comment', '--comment', '000 source destination ipv6 no cidr'],
  },
  'source_destination_ipv4_netmask' => {
    :params => {
      :name => 'source destination ipv4 netmask',
      :order => 0,
      :table => 'filter',
      :source => '1.1.1.0/255.255.255.0',
      :destination => '2.2.0.0/255.255.0.0',
    },
    :args => ['-t', :filter, '-s', '1.1.1.0/24', '-d', '2.2.0.0/16', '-p', :tcp, '-m', 'comment', '--comment', '000 source destination ipv4 netmask'],
  },
 'source_destination_ipv6_netmask' => {
    :params => {
      :name => 'source destination ipv6 netmask',
      :order => 0,
      :table => 'filter',
      :source => '2001:db8:1234::/ffff:ffff:ffff:0000:0000:0000:0000:0000',
      :destination => '2001:db8:4321::/ffff:ffff:ffff:0000:0000:0000:0000:0000',
    },
    :args => ['-t', :filter, '-s', '2001:db8:1234::/48', '-d', '2001:db8:4321::/48', '-p', :tcp, '-m', 'comment', '--comment', '000 source destination ipv6 netmask'],
  },
  'sport_range_1' => {
    :params => {
      :name => "sport range",
      :order => 100,
      :sport => ["1-1024"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "multiport", "--sports", "1:1024", "-m", "comment", "--comment", "100 sport range"],
  },
  'sport_range_2' => {
    :params => {
      :name => "sport range",
      :order => 100,
      :sport => ["15","512-1024"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "multiport", "--sports", "15,512:1024", "-m", "comment", "--comment", "100 sport range"],
  },
  'dport_range_1' => {
    :params => {
      :name => "sport range",
      :order => 100,
      :dport => ["1-1024"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "multiport", "--dports", "1:1024", "-m", "comment", "--comment", "100 sport range"],
  },
  'dport_range_2' => {
    :params => {
      :name => "sport range",
      :order => 100,
      :dport => ["15","512-1024"],
      :table => "filter",
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "multiport", "--dports", "15,512:1024", "-m", "comment", "--comment", "100 sport range"],
  },
  'dst_type_1' => {
    :params => {
      :name => 'dst_type',
      :order => 0,
      :table => 'filter',
      :dst_type => 'LOCAL',
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'addrtype', '--dst-type', :LOCAL, '-m', 'comment', '--comment', '000 dst_type'],
  },
  'src_type_1' => {
    :params => {
      :name => 'src_type',
      :order => 0,
      :table => 'filter',
      :src_type => 'LOCAL',
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'addrtype', '--src-type', :LOCAL, '-m', 'comment', '--comment', '000 src_type'],
  },
  'dst_range_1' => {
    :params => {
      :name => 'dst_range',
      :order => 0,
      :table => 'filter',
      :dst_range => '10.0.0.1-10.0.0.10',
    },
    :args => ['-t', :filter, '-m', 'iprange', '--dst-range', '10.0.0.1-10.0.0.10', '-p', :tcp, '-m', 'comment', '--comment', '000 dst_range'],
  },
  'src_range_1' => {
    :params => {
      :name => 'src_range',
      :order => 0,
      :table => 'filter',
      :dst_range => '10.0.0.1-10.0.0.10',
    },
    :args => ['-t', :filter, '-m', 'iprange', '--dst-range', '10.0.0.1-10.0.0.10', '-p', :tcp, '-m', 'comment', '--comment', '000 src_range'],
  },
  'tcp_flags_1' => {
    :params => {
      :name => "initiation",
      :order => 0,
      :tcp_flags => "SYN,RST,ACK,FIN SYN",
      :table => "filter",
    },

    :args => ["-t", :filter, "-p", :tcp, "-m", "tcp", "--tcp-flags", "SYN,RST,ACK,FIN", "SYN", "-m", "comment", "--comment", "000 initiation",]
  },
  'states_set_from_array' => {
    :params => {
      :name => "states_set_from_array",
      :order => 100,
      :table => "filter",
      :state => ['ESTABLISHED', 'INVALID']
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "comment", "--comment", "100 states_set_from_array",
      "-m", "state", "--state", "ESTABLISHED,INVALID"],
  },
  'ctstates_set_from_array' => {
    :params => {
      :name => "ctstates_set_from_array",
      :order => 100,
      :table => "filter",
      :ctstate => ['ESTABLISHED', 'INVALID']
    },
    :args => ["-t", :filter, "-p", :tcp, "-m", "comment", "--comment", "100 ctstates_set_from_array",
      "-m", "conntrack", "--ctstate", "ESTABLISHED,INVALID"],
  },
  'comment_string_character_validation' => {
    :params => {
      :name => "allow from 192.168.0.1, please",
      :order => 0,
      :table => 'filter',
      :source => '192.168.0.1'
    },
    :args => ['-t', :filter, '-s', '192.168.0.1/32', '-p', :tcp, '-m', 'comment', '--comment', '000 allow from 192.168.0.1, please'],
  },
  'port_property' => {
    :params => {
      :name => 'port property',
      :order => 1,
      :table => 'filter',
      :port => '80',
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--ports', '80', '-m', 'comment', '--comment', '001 port property'],
  },
  'log_level_debug' => {
    :params => {
      :name => 'INPUT log-level',
      :order => 956,
      :table => 'filter',
      :state => 'NEW',
      :jump => 'LOG',
      :log_level => 'debug'
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'comment', '--comment', '956 INPUT log-level', '-m', 'state', '--state', 'NEW', '-j', 'LOG', '--log-level', '7'],
  },
  'log_level_warn' => {
    :params => {
      :name => 'INPUT log-level',
      :order => 956,
      :table => 'filter',
      :state => 'NEW',
      :jump => 'LOG',
      :log_level => 'warn'
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'comment', '--comment', '956 INPUT log-level', '-m', 'state', '--state', 'NEW', '-j', 'LOG', '--log-level', '4'],
  },
  'load_limit_module_and_implicit_burst' => {
    :params => {
      :name => 'INPUT limit NTP',
      :order => 57,
      :table => 'filter',
      :dport => '123',
      :limit => '15/hour'
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--dports', '123', '-m', 'comment', '--comment', '057 INPUT limit NTP', '-m', 'limit', '--limit', '15/hour'],
  },
  'limit_with_explicit_burst' => {
    :params => {
      :name => 'INPUT limit NTP',
      :order => 57,
      :table => 'filter',
      :dport => '123',
      :limit => '30/hour',
      :burst => '10'
    },
    :args => ['-t', :filter, '-p', :tcp, '-m', 'multiport', '--dports', '123', '-m', 'comment', '--comment', '057 INPUT limit NTP', '-m', 'limit', '--limit', '30/hour', '--limit-burst', '10'],
  },
  'proto_ipencap' => {
    :params => {
      :name => 'INPUT accept ipencap',
      :order => 100,
      :table => 'filter',
      :proto => 'ipencap',
    },
    :args => ['-t', :filter, '-p', :ipencap, '-m', 'comment', '--comment', '0100 INPUT accept ipencap'],
  },
  'load_uid_owner_filter_module' => {
    :params => {
      :name => 'OUTPUT uid root only',
      :order => 57,
      :table => 'filter',
      :uid => 'root',
      :action => 'accept',
      :chain => 'OUTPUT',
      :proto => 'all',
    },
    :args => ['-t', :filter, '-p', :all, '-m', 'owner', '--uid-owner', 'root', '-m', 'comment', '--comment', '057 OUTPUT uid root only', '-j', 'ACCEPT'],
  },
  'load_uid_owner_postrouting_module' => {
    :params => {
      :name => 'POSTROUTING uid root only',
      :order => 57,
      :table => 'mangle',
      :uid => 'root',
      :action => 'accept',
      :chain => 'POSTROUTING',
      :proto => 'all',
    },
    :args => ['-t', :mangle, '-p', :all, '-m', 'owner', '--uid-owner', 'root', '-m', 'comment', '--comment', '057 POSTROUTING uid root only', '-j', 'ACCEPT'],
  },
  'load_gid_owner_filter_module' => {
    :params => {
      :name => 'OUTPUT gid root only',
      :order => 57,
      :table => 'filter',
      :chain => 'OUTPUT',
      :gid => 'root',
      :action => 'accept',
      :proto => 'all',
    },
    :args => ['-t', :filter, '-p', :all, '-m', 'owner', '--gid-owner', 'root', '-m', 'comment', '--comment', '057 OUTPUT gid root only', '-j', 'ACCEPT'],
  },
  'load_gid_owner_postrouting_module' => {
    :params => {
      :name => 'POSTROUTING gid root only',
      :order => 57,
      :table => 'mangle',
      :gid => 'root',
      :action => 'accept',
      :chain => 'POSTROUTING',
      :proto => 'all',
    },
    :args => ['-t', :mangle, '-p', :all, '-m', 'owner', '--gid-owner', 'root', '-m', 'comment', '--comment', '057 POSTROUTING gid root only', '-j', 'ACCEPT'],
  },
  'mark_set-mark_int' => {
    :params => {
      :name     => 'set-mark 1000',
      :order    => 58,
      :table    => 'mangle',
      :jump     => 'MARK',
      :chain    => 'PREROUTING',
      :set_mark => '1000',
    },
    :args => ['-t', :mangle, '-p', :tcp, '-m', 'comment', '--comment', '058 set-mark 1000', '-j', 'MARK', '--set-xmark', '0x3e8/0xffffffff'],
  },
  'mark_set-mark_hex' => {
    :params => {
      :name     => 'set-mark 0x32',
      :order    => 58,
      :table    => 'mangle',
      :jump     => 'MARK',
      :chain    => 'PREROUTING',
      :set_mark => '0x32',
    },
    :args => ['-t', :mangle, '-p', :tcp, '-m', 'comment', '--comment', '058 set-mark 0x32', '-j', 'MARK', '--set-xmark', '0x32/0xffffffff'],
  },
  'mark_set-mark_hex_with_hex_mask' => {
    :params => {
      :name     => 'set-mark 0x32/0xffffffff',
      :order    => 58,
      :table    => 'mangle',
      :jump     => 'MARK',
      :chain    => 'PREROUTING',
      :set_mark => '0x32/0xffffffff',
    },
    :args => ['-t', :mangle, '-p', :tcp, '-m', 'comment', '--comment', '058 set-mark 0x32/0xffffffff', '-j', 'MARK', '--set-xmark', '0x32/0xffffffff'],
    },
  'mark_set-mark_hex_with_mask' => {
    :params => {
      :name     => 'set-mark 0x32/4',
      :order    => 58,
      :table    => 'mangle',
      :jump     => 'MARK',
      :chain    => 'PREROUTING',
      :set_mark => '0x32/4',
    },
    :args => ['-t', :mangle, '-p', :tcp, '-m', 'comment', '--comment', '058 set-mark 0x32/4', '-j', 'MARK', '--set-xmark', '0x32/0x4'],
    },
    'iniface_1' => {
    :params => {
      :name => 'iniface',
      :order => 60,
      :table => 'filter',
      :action => 'drop',
      :chain => 'INPUT',
      :iniface => 'eth0',
    },
    :args => ["-t", :filter, "-i", "eth0", "-p", :tcp, "-m", "comment", "--comment", "060 iniface", "-j", "DROP"],
  },
  'iniface_with_vlans_1' => {
    :params => {
      :name => 'iniface',
      :order => 60,
      :table => 'filter',
      :action => 'drop',
      :chain => 'INPUT',
      :iniface => 'eth0.234',
    },
    :args => ["-t", :filter, "-i", "eth0.234", "-p", :tcp, "-m", "comment", "--comment", "060 iniface", "-j", "DROP"],
  },
  'iniface_with_plus_1' => {
    :params => {
      :name => 'iniface',
      :order => 60,
      :table => 'filter',
      :action => 'drop',
      :chain => 'INPUT',
      :iniface => 'eth+',
    },
    :args => ["-t", :filter, "-i", "eth+", "-p", :tcp, "-m", "comment", "--comment", "060 iniface", "-j", "DROP"],
  },
  'outiface_1' => {
    :params => {
      :name => 'outiface',
      :order => 60,
      :table => 'filter',
      :action => 'drop',
      :chain => 'OUTPUT',
      :outiface => 'eth0',
    },
    :args => ["-t", :filter, "-o", "eth0", "-p", :tcp, "-m", "comment", "--comment", "060 outiface", "-j", "DROP"],
  },
  'outiface_with_vlans_1' => {
    :params => {
      :name => 'outiface',
      :order => 60,
      :table => 'filter',
      :action => 'drop',
      :chain => 'OUTPUT',
      :outiface => 'eth0.234',
    },
    :args => ["-t", :filter, "-o", "eth0.234", "-p", :tcp, "-m", "comment", "--comment", "060 outiface", "-j", "DROP"],
  },
  'outiface_with_plus_1' => {
    :params => {
      :name => 'outiface',
      :order => 60,
      :table => 'filter',
      :action => 'drop',
      :chain => 'OUTPUT',
      :outiface => 'eth+',
    },
    :args => ["-t", :filter, "-o", "eth+", "-p", :tcp, "-m", "comment", "--comment", "060 outiface", "-j", "DROP"],
  },
  'pkttype multicast' => {
    :params => {
      :name => 'pkttype multicast',
      :order => 62,
      :table => "filter",
      :action => 'accept',
      :chain => 'INPUT',
      :iniface => 'eth0',
      :pkttype => 'multicast',
    },
    :args => ["-t", :filter, "-i", "eth0", "-p", :tcp, "-m", "pkttype", "--pkt-type", :multicast, "-m", "comment", "--comment", "062 pkttype multicast", "-j", "ACCEPT"],
  },
  'socket_option' => {
    :params => {
      :name => 'socket option',
      :order => 50,
      :table => 'mangle',
      :action => 'accept',
      :chain => 'PREROUTING',
      :socket => true,
    },
    :args => ['-t', :mangle, '-p', :tcp, '-m', 'socket', '-m', 'comment', '--comment', '050 socket option', '-j', 'ACCEPT'],
  },
  'isfragment_option' => {
    :params => {
      :name => 'isfragment option',
      :order => 50,
      :table => 'filter',
      :proto => :all,
      :action => 'accept',
      :isfragment => true,
    },
    :args => ['-t', :filter, '-p', :all, '-f', '-m', 'comment', '--comment', '050 isfragment option', '-j', 'ACCEPT'],
  },
  'isfragment_option not changing -f in comment' => {
    :params => {
      :name => 'testcomment-with-fdashf',
      :order => 50,
      :table => 'filter',
      :proto => :all,
      :action => 'accept',
    },
    :args => ['-t', :filter, '-p', :all, '-m', 'comment', '--comment', '050 testcomment-with-fdashf', '-j', 'ACCEPT'],
  },
}
