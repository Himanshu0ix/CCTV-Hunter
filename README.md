## CCTV-Hunter ##

<p align="center">
  <img src="https://github.com/Himanshu0ix/CCTV-Hunter/blob/main/banner.gif" width="220">
</p>

---

Let's say you got a bunch of full 100 + IPs and you have to recon  which ip is open so that you can dig deep, going through each ip and scanning will get you  full of burden and Time wasting isn't it ? 
you can't scan each IP one by one through N-map or shodan
So that's where I bulit cctv-scanner tool Beacause I needed automation that actucally respects my time.
But This is not a "security tool".
This is recon at scale.

This Tool fires **asynchronous TCP** probes that go through IP lists without waiting around for timeouts like traditional scanners. It identifies open ports which IP will be **accessible** & which ports is **Inaccessible**.
You have to only give a file path of 100+ cctv ip and just sit back in a minute you will have all open ports of cctv ip's which you can access 

# **Disclaimer** #
>This tool may take some time to complete scans, though performance improvements will continue in future updates.
>If a port appears closed in the scan but open on Shodan, it does not mean the tool is giving false results. This usually indicates one of the following:
>The target IP is not accessible from your region/network
>The service is using UDP, which this tool does not probe

## Use (Linux Distro) ##
---
```
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git -y
git clone https://github.com/Himanshu0ix/CCTV-Hunter
cd CCTV-Scanner
pip3 install -r requirements.txt
chmod +x install.sh
./install.sh
python3 cctv_scanner.py --help
```
---
## Use (Termux) ##
```
pkg update && pkg upgrade -y
pkg install python git
git clone https://github.com/Himanshu0ix/CCTV-Hunter
cd CCTV-Scanner
pip install -r requirements.txt
chmod +x install.sh
./install.sh
python3 cctv_scanner.py --help
```
## Usage Examples ##
> Scan a single IP
```
python3 cctv_scanner.py --manual 192.168.1.10 --yes
```

>Scan a file containing 100+ IPs
```
python3 cctv_scanner.py -f targets.txt --yes
```
>Save output as JSON
```
python3 cctv_scanner.py -f targets.txt --yes --json-output results.json

```
* Have fun! (support me with star ⭐ !!)

## Education Guidelines ##

* CCTV-Hunter is developed for learning, research, and authorized security testing only.
+ Use this tool to understand how network reconnaissance works, how IoT devices expose services, and how fingerprinting techniques identify vendors and endpoints.
You are expected to:
+ Follow ethical hacking principles
- Scan only systems you own or have explicit permission to test
* Use the results responsibly for education, research, or improving security posture
Any misuse including unauthorized access, scanning random hosts, or violating regional laws is strictly prohibited and is the sole responsibility of the user.
