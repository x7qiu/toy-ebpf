# Env Setup (Tested on Ubuntu 24.04)
```bash
# system dependency
sudo apt update
sudo apt install -y golang clang llvm libbpf-dev build-essential
# ebpf dependency
sudo apt install -y linux-headers-$(uname -r)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
# (optional) bypass GFW 
go env -w GOPROXY=https://goproxy.cn,direct
go env -w GOSUMDB=sum.golang.google.cn
# go modules
go get github.com/cilium/ebpf
go get github.com/google/gopacket
```

# Running the code
```bash
go generate ./...
sudo -E go run . --iface enp0s1 --duration 10s
```