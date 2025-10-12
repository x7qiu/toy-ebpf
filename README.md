# system dependencies 
sudo apt update
sudo apt install -y golang clang llvm libbpf-dev build-essential

# ebpf dependencies
sudo apt install -y linux-headers-$(uname -r)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# (optional) bypass GFW 
go env -w GOPROXY=https://goproxy.cn,direct
go env -w GOSUMDB=sum.golang.google.cn

# go dependencies
go get github.com/cilium/ebpf
go get github.com/google/gopacket

# running the code
go generate ./...
sudo -E go run .