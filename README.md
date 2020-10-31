# raat
Routing Announcement Alfred Through

This is a concept of the dynamic announce mechanism which uses B.A.T.M.A.N. and A.L.F.R.E.D. as a background for spreading and getting static routes between MESH nodes without any other dynamic route protocols.

![Concept of network](https://github.com/nickbash11/raat/blob/master/raat-network.png)

The idea was taken from BMX6/BMX7 mesh daemon, which able to use a global cloud network and share local networks behind it between each other. So, I decided to do something like that with batman-adv, but without any BGP/OLSR addition protocols.
The example of such network presented on the screen above, where batman interface of each node has the mask 172.16.0.0/16 and also has some amount other networks behind it. In this case each node has also an additional network with mask 27 with the same (as a cloud) ip address for clarity.

For example, we want the PC2 could reach to the PC4 and vice versa, so we have to do some manupilations with iproute2:

On the NODE04:
```ip route add 172.16.200.0/27 via 172.16.200.1```

On the NODE03:
```ip route add 172.16.150.0/27 via 172.16.150.1```

Then PC2 and PC4 will be able to see each other, so, the RAAT daemon doing this automatically through A.L.F.R.E.D.



```
Usage: raat -i bat0

	-i	Batman or bridge interface which contains batman
		interface. This interface's ipv4 address
		will be announced as a route for other nodes 
	-w	Publish WAN interface as a default route>
	-l	Publish LAN routes. For now it finds br-lan interfaces
	-s 10	Range between push and pull operations
		(default 10 seconds), can be from 1 to 60
	-b 5	How many times to wait until a node will be
		considered as a dead (default 5 times). It
		depends on -s and can be from 1 to 30
	-t 100	Data type in alfred space, from 0 to 255
	-D	Enable debug mode
	-h	Show this help
```
