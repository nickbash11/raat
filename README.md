# raat
Routing Announcement Alfred Through

It is a concept of the dynamic announce mechanism which uses B.A.T.M.A.N. and A.L.F.R.E.D. as a background for spreading and getting static routes between MESH nodes without any other dynamic route protocols.

![Concept of network](https://github.com/nickbash11/raat/blob/master/raat-network.png)


Usage: raat -i bat0

	-i      Batman or bridge interface which contains batman
          interface. This interface's ipv4 address
          will be announced as a route for other nodes 
  -w      Publish WAN interface as a default route
	-l	    Publish LAN routes. For now it finds br-lan interfaces
	-s 10		Range between push and pull operations
			    (default 10 seconds), can be from 1 to 60
	-b 5		How many times to wait until a node will be
			    considered as a dead (default 5 times). It
			    depends on -s and can be from 1 to 30
	-t 100	Data type in alfred space, from 0 to 255
	-D		  Enable debug mode
	-h		  Show this help
