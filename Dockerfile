# Useful for testing on non-apt systems
# For SELinux enabled systems using run container mounting the target/debug path
# podman container run -v $(realpath target/debug):/root/bin:z -ti <image>
from debian:bookworm
run apt update && apt install -y neovim
run apt install -y emacs
run apt install -y vim
run mkdir -p /root/bin
workdir /root/bin
