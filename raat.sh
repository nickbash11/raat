#!/bin/sh

# Routing Announcement Alfred Through

if [[ -z $(uci -q get network.mesh.ifname) ]]
then
	exit 0
fi

RFILE=/etc/iproute2/rt_tables
MESH_IFACE=$(uci -q get network.mesh.ifname)
MESH_ADDR=$(uci -q get network.mesh.ipaddr)

# https://stackoverflow.com/a/52443842/5714268
PoorMansRandomGenerator () {
	local digits="${1}" # The number of digits to generate
	local number

	# Some read bytes can't be used, se we read twice the number of required bytes
	dd if=/dev/urandom bs=$digits count=2 2> /dev/null | while read -r -n1 char
	do
		number=$number$(printf "%d" "'$char")
		if [ ${#number} -ge $digits ]
		then
			echo ${number:0:$digits}
			break
		fi
	done
}

# Collecting routes to push
local_routes () {
	if [[ -z "$wan_iface_exists" ]] || [[ -z "$wan_route_exists" ]] && [[ -z "$lan_networks" ]]
	then
		echo none
		exit 0
	fi

	if [[ ! -z "$wan_iface_exists" ]] && [[ ! -z "$wan_route_exists" ]]
	then 
		echo $wan_route_exists via $MESH_ADDR
	fi

	if [[ ! -z "$lan_networks" ]]
	then
		for i in $lan_networks
		do
			echo $i via $MESH_ADDR
		done
	fi
}

# Deleting routes 
delete_routes () {
	# ip route show table 16:07:71:6b:ec:1a | while read -r f1 f2 f3 rest; do echo $f1 $f2 $f3; done 
	ip route show table $mac | awk '{print $1" "$2" "$3}' | while read -r line
	do
		if [[ -z "$(echo "$data100"  | grep $mac | awk -F"," '{print $2}' | sed  's/ "//g;s/"//g;s/\\x0a/\n/g;s/ }//g' | sed '/^$/d' | grep "$line")" ]]
		then
			echo ip route del $line table $mac
			logger -t RAAT ip route del $line table $mac
			ip route del $line table $mac

			if [[ -z "$(echo $line | grep default)" ]]
			then
				echo ip rule del from all to $(echo $line | awk '{print $1}') table $mac
				logger -t RAAT ip rule del from all to $(echo $line | awk '{print $1}') table $mac
				ip rule del from all to $(echo $line | awk '{print $1}') table $mac
			else
				echo ip rule del from all priority 33333 table $mac
				logger -t RAAT ip rule del from all priority 33333 table $mac
				ip rule del from all priority 33333 table $mac
			fi
		fi
	done
}

# Adding routes
add_routes () {
	echo "$data100" | grep $mac | awk -F"," '{print $2}' | sed  's/ "//g;s/"//g;s/\\x0a/\n/g;s/ }//g' | sed '/^$/d' | grep -v none | while read -r line
	do
		if [[ -z "$(ip route show table $mac | grep "$line")" ]]
		then
			echo ip route add $line table $mac
			logger -t RAAT ip route add $line table $mac
			ip route add $line table $mac
		fi

		if [[ -z "$(echo $line | grep default)" ]] && [[ -z "$(ip rule | grep "$(echo $line | awk '{print $1}')")" ]]
		then
			echo ip rule add from all to $(echo $line | awk '{print $1}') table $mac
			logger -t RAAT ip rule add from all to $(echo $line | awk '{print $1}') table $mac
			ip rule add from all to $(echo $line | awk '{print $1}') table $mac
		elif [[ ! -z "$(echo "$data100" | grep $mac | grep default)" ]] && [[ -z "$(ip rule | grep $mac | grep 33333)" ]]
		then
			echo ip rule add from all priority 33333 table $mac
			logger -t RAAT ip rule add from all priority 33333 table $mac
			ip rule add from all priority 33333 table $mac
		fi
	done
}

# The main function
main () {
	tempfile=/tmp/finished.$$
	echo "$data100" | grep -v $mesh_mac | while read -r data
	do
		if [[ -z "$data100" ]]
		then
			break
		fi

		(
			mac=$(echo $data | awk -F'"' '{print $2}')
			number=$(cat $RFILE | grep $mac | awk '{print $1}')

			if [[ -z "$number" ]] 
			then
				while true
				do
					number=$(PoorMansRandomGenerator 3)
					if [[ -z "$(cat $RFILE | grep $number)" ]]
					then
						echo "$number	$mac # alive" >> $RFILE
						logger -t RAAT a new $mac is alive
						break
					fi
				done
			fi

			batctl ping -c 2 $mac > /dev/null
			if [[ $? -ne 0 ]]
			then
				if [[ ! -z "$(grep "$mac # alive" $RFILE)" ]]
				then
					echo $mac is wait
					logger -t RAAT $mac is wait
					sed -i "s/$number	$mac # alive/$number	$mac # wait/" $RFILE
				elif [[ ! -z "$(grep "$mac # wait" $RFILE)" ]]
				then
					echo $mac is dead
					logger -t RAAT $mac is dead
					sed -i "s/$number	$mac # wait/$number	$mac # dead/" $RFILE

					ip rule | grep "$mac" | awk '{$1=""}1' | while read -r rule_del
					do
						echo ip rule del $rule_del
						logger -t RAAT ip rule del $rule_del
						ip rule del $rule_del
					done
				fi
			else
				if [[ ! -z "$(grep "$mac # wait" $RFILE)" ]]
				then
					echo $mac is alive
					logger -t RAAT $mac is alive
					sed -i "s/$number	$mac # wait/$number	$mac # alive/" $RFILE
				elif [[ ! -z "$(grep "$mac # dead" $RFILE)" ]]
				then
					echo $mac is alive
					logger -t RAAT $mac is alive
					sed -i "s/$number	$mac # dead/$number	$mac # alive/" $RFILE
				fi

				add_routes
				delete_routes
			fi
			touch $tempfile
		) &
	done
	while ! test -f $tempfile; do sleep 1; done
	sleep 1
	rm -f $tempfile
}

# Clear orphaned rules
orph_clear () {
	cat $RFILE | awk '{print $2" "$3}' | grep "#" | awk '{print $1}' | while read -r mac
	do
		if [[ -z "$(echo "$data100" | grep -v $mesh_mac | grep "$(echo $mac)")" ]]
		then
			logger -t RAAT orphaned host $mac has been cleared
			echo orphaned host $mac has been cleared
			ip route show table $mac | while read -r route
			do
				logger -t RAAT ip route del $route table $mac
				echo ip route del $route table $mac
				ip route del $route table $mac
			done
	
			if [[ ! -z "$(ip rule show | grep $mac)" ]]
			then
				ip rule show | grep $mac | awk '{$1=""}1' | while read -r rule_del
				do
					logger -t RAAT ip route del $rule_del
					echo ip rule del $rule_del
					ip rule del $rule_del
				done
			fi

			sed -i "/$mac/d" $RFILE
		fi
	done
}

while true
do
	data100=$(alfred -r 100)
	mesh_mac=$(ip addr show dev $MESH_IFACE | grep link/ether | awk '{print $2}')
	lan_networks=$(ip route | awk '/ dev br-/ {print $1}')
	wan_iface_exists=$(uci -q get network.wan.ifname)
	wan_route_exists=$(ip route | grep -w "$wan_iface_exists" | awk '/default / {print $1}')

	local_routes | alfred -s 100
	sleep 20 
	main
	orph_clear
done
