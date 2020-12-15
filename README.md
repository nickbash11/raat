# Routing Announcement Alfred Through

## About

This is a concept of the dynamic announce mechanism which uses B.A.T.M.A.N. and A.L.F.R.E.D. as a background for spreading and getting static routes between MESH nodes without any other dynamic route protocols.

The idea was taken from BMX6/BMX7 mesh daemon, which is able to use a global cloud network and share local networks behind them between each other. So, I decided to do something like that with batman-adv, but nothing BGP/OLSR addition protocols.

It uses [UTHASH](https://troydhanson.github.io/uthash/) macros header to implement holding the information about nodes and routes in memory.

## How it works

The example of such network presented on the screen below, where the batman interface (bat0) of each node has the mask 172.16.0.0/16. In this case each node has also an additional local network (br-lan) with mask 27 with the same (as a cloud) ip address for clarity, it might have any network mask.

![Concept of network](https://github.com/nickbash11/raat/blob/master/raat-network.png)


For example, we want the PC2 could reach to the PC4 and vice versa, so we have to do some manupilations with iproute2 command line like that:

On the NODE04:
```ip route add 172.16.200.0/27 via 172.16.200.1```

On the NODE03:
```ip route add 172.16.150.0/27 via 172.16.150.1```

Then PC2 and PC4 will be able to see each other, so, the **raat** daemon doing this automatically through A.L.F.R.E.D.

It pushes its own routes to and pulls them from other participants of the MESH network. Now it uses iproute2 via pipe to manage routing table.

## Default routes

raat can pick the best quality default route by using TQ from "batctl o"

## Get and compilation

```
$ git clone https://github.com/nickbash11/raat.git
$ cd raat/src
$ make && strip raat
```

## Use

**Of course, before using you have to have working BATMAN network and installed and running ALFRED daemon.**

In simple case you can only tell to the RAAT the BATMAN interface

```
# ./raat -i bat0
```

Or you would like to publish your lans and wan (if those are exist):

```
# ./raat -i bat0 -l -w
```

Then in a few moment later, you can see the status of the available routes by using option -I:

```
# ./raat -I
last update: 2020-11-30 16:34:44

push:
mac			ipv4		routes
ea:59:11:5e:35:31	172.16.50.1	172.16.50.0/27*

pull:
mac			originator		timestamp	breakups	ipv4		routes
b6:95:72:31:11:d5	00:00:00:dd:aa:cc	1606743271	0		172.16.150.1	172.16.150.0/27*
a2:c5:b0:c1:41:90	08:00:27:b5:63:b1	1606743275	0		172.16.200.1	default*172.16.200.0/27*

default route:
4e:20:5a:01:e4:33	00:00:00:44:22:11	1606743274	0		172.16.100.1	default*172.16.100.0/27*

```

At the same time you can see in your rule table something like:

```
# ip rule
0:	from all lookup local 
30000:	from all to 172.16.150.0/27 lookup 858
30000:	from all to 172.16.200.0/27 lookup 573
30000:	from all to 172.16.100.0/27 lookup 336
32766:	from all lookup main
32767:	from all lookup default
33333:	from all lookup 336
```

Where the priorities 30000 and 33333 are controlled by RAAT.

To kill the daemon properly use QUIT:

```
$ sudo kill -QUIT `cat /var/run/raat.pid`
```

## OpenWRT

Mainly it has been developed for OpenWRT and testing on it, so you can find out how to use an OpenWRT SDK to compile RAAT for other than x86_64 platforms by going to [wiki page.](https://github.com/nickbash11/raat/wiki/RAAT-for-OpenWRT)

## Command line options

```
Usage: raat -i bat0

	-i interface	Batman or bridge interface which contains batman
			interface. This interface's ipv4 address
			will be announced as a route for other nodes
        -w		Publish WAN interface as a default route
	-l		Publish LAN routes. For now it finds br-lan interfaces
	-s 10		Range between push and pull operations
			(default 10 seconds), can be from 1 to 60
	-b 5		How many times to wait until a node will be
			considered as a dead (default 5 times). It
			depends on -s and can be from 1 to 30
	-t 100		Data type in alfred space, from 64 to 255
	-I		Get the information from shared memory
	-v		Show version
	-h		Show this help
```

## Testing

I test raat in virtualbox. For emulate wifi devices you can use the project from [Raizo62](https://github.com/Raizo62/vwifi)

## Thoughts

* This time raat uses timestamps for evaluate the availability of a node, when breakups exceed a threshold then a node means as a dead. I think that it can have another approach by using "TQ" or "last-seen" for this goal.

* Raat uses pipes for manage all its communications between alfred, ip routing and batman. Instead, it has to use native functions and sockets to communicate. UDS for alfred, functions from batctl, and netlink to control routing tables and rules.

