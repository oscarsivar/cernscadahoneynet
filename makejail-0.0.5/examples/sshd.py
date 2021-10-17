chroot="/var/chroot/cshoneynet"
forceCopy=["/var/cshoneynet/"]

users=["cshoneynet"]
groups=["cshoneynet"]
testCommandsInsideJail=["/usr/local/bin/honeyd -i eth0 -u 6666 -g 6666 -l /var/cshoneynet/logs/l.log -s /var/cshoneynet/logs/s.log -f /var/cshoneynet/conf/honeyd.conf.t1 137.138.251.81-137.138.251.82"]
testCommandsOutsideJail=["telnet 137.138.251.81 502"]
processNames=["honeyd"]
