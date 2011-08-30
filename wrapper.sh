IP=`busybox ifconfig rmnet0 | busybox grep addr: | busybox awk '{print $2}' | busybox sed 's/addr://g'`
#IP=21.217.131.214
#/data/local/bin/busybox ip link add type veth
#/data/local/bin/busybox ip link add type veth
/data/local/bin/busybox ifconfig veth0 mtu 1400 up
/data/local/bin/busybox ifconfig veth1 mtu 1400 up
/data/local/bin/busybox ifconfig veth2 mtu 1400 up
/data/local/bin/busybox ifconfig veth3 mtu 1400 up
/data/local/bin/wrapper rmnet0 veth3 $IP
