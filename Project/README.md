# isis-mocker

Tool provides replication (injection) of exported ISIS(RFC 1195) database in json format to a lab router.
_ONLY_ L2 P2P adjacency supported and Linux OS. To get input json file in correct format see details below.

#### Features supported
* Base ISIS protocol structs
* IPv4 reachability
* Basic SR


#### Encoded params
Tool uses the following parameters as encoded:

* MAC address: 00:0c:29:6f:14:bf
* NET address: 0001.0000.0001.00
* AREA address: 49.0001
* IP address/mask: 10.100.0.1 255.255.255.254

#### Installation and run
Get .deb package, install using pkg manager.

since version 0.0.9 supported default params change, for example:
```
isis-mocker --ifname eth1 --json-file out.json --ipaddress 10.102.0.1 --dut_ipaddress 10.102.0.0 --hostname m1 --sysid 0010.0010.0010 --dut_sysid 0003.0003.0003
```

#### JSON preparation
* Get 2 outputs from Junos router:
    show isis database extensive | display json | no-more
    show isis hostname | display json | no-more

*  Use py script to create json in the correct format*, for example
   ./convert-showisisdb.py --filepath \`pwd\` --hosts jtac-hosts-isis-json.txt --sourcedb jtac-db-isis-json.txt --output out.json

*  Run the program providing json file and nic name, for example:
   ./isis-mocker eth1 out.json

\* Junos implementation of isis json export for older releases produces duplicate json keys(not recommended by standard), also lsp-ids are exported as hostnames.


#### Sample outputs
DUT(device under test) router config example:
```
Cisco IOS-XR

router isis 1
 net 49.0004.0004.0004.0004.00
 address-family ipv4 unicast
 !
 interface GigabitEthernet0/0/0/1
  circuit-type level-2-only
  point-to-point
  address-family ipv4 unicast
  !

interface GigabitEthernet0/0/0/1
 ipv4 address 10.100.0.0 255.255.255.254
!

Junos

interfaces {
      lo0 {
        unit 0 {
            family iso {
                address 49.0004.0004.0004.0004.00;
            }
        }
      ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.100.0.0/31;
            }
            family iso;
            family mpls;
        }
    }
}

protocols {
      isis {
        interface ge-0/0/1.0 {
            point-to-point;
        }
        interface lo0.0;
         source-packet-routing {
            srgb start-label 100000 index-range 36000;
        }
        level 1 disable;
        level 2 wide-metrics-only;
     }
       mpls {
        interface all;
     }
}
```

Sample run:
```
root@salt:/var/tmp/fresh# isis-mocker eth1 out.json | more

  ___ ____ ___ ____        __  __  ___   ____ _  _______ ____
 |_ _/ ___|_ _/ ___|      |  \/  |/ _ \ / ___| |/ / ____|  _ \
  | |\___ \| |\___ \ _____| |\/| | | | | |   | ' /|  _| | |_) |
  | | ___) | | ___) |_____| |  | | |_| | |___| . \| |___|  _ <
 |___|____/___|____/      |_|  |_|\___/ \____|_|\_\_____|_| \_\
 version: 0.0.5
Loading JSON ...
done
Found LSPs: 3284
LSP-ID 0000.0000.0000.00-00
LSP-ID 0000.0000.0001.00-00
LSP-ID 0000.0000.0002.00-00
LSP-ID 0000.0000.0003.00-00
LSP-ID 0000.0000.0004.00-00
LSP-ID 0000.0000.0005.00-00
LSP-ID 0000.0000.0006.00-00
LSP-ID 0000.0000.0007.00-00
LSP-ID 0000.0000.0008.00-00
LSP-ID 0204.3ee1.10b0.00-00
hostname: DA1-EA1
LSP-ID 0204.3ee1.10b1.00-00
hostname: DA1-EB1
LSP-ID 0204.3ee1.10b2.00-00
hostname: DA1-SA2
LSP-ID 0204.3ee1.10b2.00-01
LSP-ID 0204.3ee1.10b3.00-00
hostname: DA1-SB2

<snip>

ISIS Adj is : Down
ISIS Adj is : Init
ISIS Adj is : Up

flooding LSPs to DUT



root@Junos-DUT> show isis adjacency
Interface             System         L State        Hold (secs) SNPA
ge-0/0/1.0            isis-mocker    2  Up                   29   <----


root@Junos-DUT> show isis database
IS-IS level 1 link-state database:
  0 LSPs

IS-IS level 2 link-state database:
LSP ID                      Sequence Checksum Lifetime Attributes
0000.0000.0000.00-00           0xdbc   0x828a    65080 L1 L2
0000.0000.0001.00-00           0xdbc   0xa4f1    65080 L1 L2
0000.0000.0002.00-00           0xdbc   0x1da3    65080 L1 L2
0000.0000.0003.00-00           0xdbc   0x335d    65080 L1 L2
0000.0000.0004.00-00           0xdbc   0x322c    65080 L1 L2
0000.0000.0005.00-00           0xdbc   0xf594    65080 L1 L2
0000.0000.0006.00-00           0xdbc   0x6751    65080 L1 L2
0000.0000.0007.00-00           0xdbc   0x5034    65080 L1 L2
0000.0000.0008.00-00           0xdbc   0xb301    65080 L1 L2
isis-mocker.00-00                0x1   0x84c7     1075 L1 L2
Junos-DUT.00-00                  0x2   0x30e9     1173 L1 L2
DA1-EA1.00-00                   0xe3   0x54a5    59172 L1 L2
DA1-EB1.00-00                0x14b7c   0x9e64    39412 L1 L2
DA1-SA2.00-00                0x22b24   0x56ea    36636 L1 L2
DA1-SA2.00-01                 0x115e   0x4788    36655 L1 L2
DA1-SB2.00-00                0x1c5a3   0xb029    65503 L1 L2
DA1-SB2.00-01                 0x787c   0x5387    65503 L1 L2
DA1-RRA3.00-00                 0x18e   0x128c    39509 L1 L2
<snip>

root@Junos-DUT> show isis database | match LSPs
  0 LSPs
  3286 LSPs

root@Junos-DUT> show route summary
Router ID: 5.5.5.5

Highwater Mark (All time / Time averaged watermark)
    RIB unique destination routes: 17168 at 2023-04-19 19:58:52 / 0
    RIB routes                   : 17170 at 2023-04-19 19:58:52 / 0
    FIB routes                   : 13941 at 2023-04-19 19:58:55 / 0
    VRF type routing instances   : 0 at 2023-04-19 19:44:11

inet.0: 10730 destinations, 10731 routes (10730 active, 0 holddown, 0 hidden)
              Direct:      4 routes,      4 active
               Local:      3 routes,      3 active
               IS-IS:  10723 routes,  10722 active   <----
     Access-internal:      1 routes,      1 active

inet.3: 3199 destinations, 3199 routes (3199 active, 0 holddown, 0 hidden)
              L-ISIS:   3199 routes,   3199 active

iso.0: 1 destinations, 1 routes (1 active, 0 holddown, 0 hidden)
              Direct:      1 routes,      1 active

mpls.0: 3217 destinations, 3217 routes (3217 active, 0 holddown, 0 hidden)
                MPLS:      6 routes,      6 active
              L-ISIS:   3211 routes,   3211 active  <----

inet6.0: 2 destinations, 2 routes (2 active, 0 holddown, 0 hidden)
               Local:      1 routes,      1 active
               INET6:      1 routes,      1 active

inetcolor.0: 10 destinations, 10 routes (10 active, 0 holddown, 0 hidden)
              L-ISIS:     10 routes,     10 active

```


#### License and deps

libc6 (>= 2.14), libgcc-s1 (>= 3.0), libstdc++6 (>= 9)

Jan 2023. Application isis-mocker is an Open Source software. It may be used for any purpose, including commercial purposes,
at absolutely no cost. It is distributed under the terms of the MIT license.
