# RFC 6056 Device Tracker

This repository contains a prototype implementation of a device tracking technique for Linux-based devices by exploiting Algorithm 4 ("Double-Hash Port Selection Algorithm") of RFC 6056. This algorithm is used in Linux for selecting TCP source ports starting from kernel version `5.12-rc1`.

The main idea is that we find hash collisions of the `G()` function when used with loopback TCP connections (`127.0.0.0/8` to `127.0.0.0/8`). These collisions are network independent: they rely only on the key used with `G()`, and as such, the set (or a subset) of `G()` collisions can be used as a device ID, for the lifetime of the key (in Linux, until the device is rebooted). 

By sampling TCP source ports originated from the victim device and generated in an attacker-perscribed manner, we can detect the loopback collisions *remotely*. This allows us to track devices via the browser. Since we only care about the source port, a full TCP connection need not be established -- it suffices that the attacker will capture a TCP SYN packet originated from the victim device and then reset the connection.

This prototype contains a tracking server written in Go and a tracking client written in HTML+JavaScript. The Linux kernel issue is tracked as CVE-2022-32296.

For full details and analysis of the attack, please refer to our paper "Device Tracking via Linux's New TCP Source Port Selection Algorithm" by Moshe Kol, Amit Klein and Yossi Gilad, to be presented on USENIX Security '23.

## Which Linux kernel versions are affected?

Linux switched from Algorithm 3 of RFC 6056 to Algorithm 4 starting from kernel version `5.12-rc1`, by commit 190cc82489f4 ("tcp: change source port randomizarion [sic] at connect() time").
The issue was [fixed](https://lwn.net/ml/linux-kernel/20220427065233.2075-1-w@1wt.eu/) in versions `5.17.9` (and above) and `5.15.41` (the LTS version that include the vulnerability). 

You can use our tool (availble as a Python script `CVE-2022-32296_tester.py`) to detect whether your Linux machine is vulnerable or not.

## Which browsers can be used for tracking?

We tested our prototype on Google Chrome v96.0.4664.110 and Mozilla Firefox v96.0. Our implementation works best on Chrome. (Please see the paper for details.)

## How long does it take to produce a device ID?

On Chrome, it takes between 5 to 15 seconds, depending on the RTT to the tracking server.

## What are the limitations of this technique? 

Our technique relies on sampling TCP source ports originated from the tracked client. Consequently, a NAT device which rewrites TCP source ports causes our attack to fail. Similarly, our technique cannot track clients that connect via forward proxies, which establish a new TCP connection to the tracking server (instead of a direct connection from the client). In particular, Tor clients are not affected.

## How can I protect my system?

It's best that you update your Linux kernel to the patched versions: 5.17.9 (and above) or 5.15.41 (and above) if your system uses the 5.15 LTS branch.

## How can I experiment with this technique?

You can experiment with our prototype with the following steps:

1\. Compile the tracker and run it.

Compile the tracker with:

```
$ sudo apt update
$ sudo apt install golang-go libpcap-dev

# on the project directory
$ go get github.com/google/gopacket
$ go get github.com/google/gopacket/pcap

# now you can build
$ go build -o tracker tracker.go
```

Run it with:

```
sudo ./tracker -iface <capturing-interface>
```

To run the server on your loopback interface, replace `<capturing-interface>` with `lo`.

2\. Access the tracker via the browser. (Make sure your OS runs on an affected Linux kernel version.)

3\. Type the tracker IP address on the "Tracker address" field.

4\. Hit "Fingerprint me!".

You should see the same fingerprint generated on each run.