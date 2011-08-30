IP=`busybox ifconfig rmnet0 | busybox grep addr: | busybox awk '{print $2}' | busybox sed 's/addr://g'`
NET=`echo $IP | busybox sed 's/.[0-9]*//4'`
#/data/local/bin/busybox ip link add type veth
#/data/local/bin/busybox ip link add type veth
/data/local/bin/busybox ifconfig veth0 mtu 1400 up
/data/local/bin/busybox ifconfig veth1 mtu 1400 up
/data/local/bin/busybox ifconfig veth2 mtu 1400 up
/data/local/bin/busybox ifconfig veth3 mtu 1400 up
#/data/local/bin/busybox ifconfig rmnet0 0.0.0.0
/data/local/bin/busybox ip route del dev rmnet0
/data/local/bin/busybox route del -net $NET.0 netmask 255.255.255.0 rmnet0
/data/local/bin/busybox ifconfig veth2 $IP netmask 255.255.255.0
/data/local/bin/busybox route del -net $NET.0 netmask 255.255.255.0 veth2
/data/local/bin/busybox route add default dev veth2
/data/local/bin/wrapper rmnet0 veth3 $IP
