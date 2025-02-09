#!/bin/bash

echo "[*] Adding i386 architecture and updating package list..."
sudo dpkg --add-architecture i386 && \
sudo apt-get -y update

echo "[*] Installing essential packages..."
sudo apt install -y \
    sudo \
    libc6:i386 \
    libc6-dbg:i386 \
    libc6-dbg \
    libffi-dev \
    libssl-dev \
    liblzma-dev \
    ipython3 \
    net-tools \
    python3-dev \
    python3-pip \
    build-essential \
    ruby \
    ruby-dev \
    strace \
    ltrace \
    binwalk \
    nasm \
    wget \
    gdb \
    gdb-multiarch \
    netcat \
    git \
    zsh \
    patchelf \
    file \
    python3-distutils \
    zstd \
    ripgrep \
    python-is-python3 \
    tzdata --fix-missing

echo "[*] Cleaning up apt cache..."
sudo rm -rf /var/lib/apt/list/*

echo "[*] Installing one_gadget and seccomp-tools gems..."
sudo gem install one_gadget seccomp-tools
sudo rm -rf /var/lib/gems/2.*/cache/*

echo "[*] Upgrading pip and installing pwntools..."
python3 -m pip install -U pip
python3 -m pip install --no-cache-dir pwntools

echo "[*] Installing Zsh plugins..."
sudo apt-get install zsh-syntax-highlighting -y
git clone https://github.com/zsh-users/zsh-autosuggestions ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-completions ~/.oh-my-zsh/custom/plugins/zsh-completions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting

echo "[*] Configuring Zsh plugins in .zshrc..."
sed -i '/^plugins=/c\plugins=(git zsh-autosuggestions zsh-completions zsh-syntax-highlighting)' ~/.zshrcsource ~/.zshrc

echo "[*] Adding PATH and PYTHONPATH to .zshrc and Setup custom tools..."
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
echo 'export PYTHONPATH=~/custom_libs:$PYTHONPATH' >> ~/.zshrc
chmod +x crun
chmod +x genpwn
chmod +x subl
chmod +x ida64
chmod +x ida
sudo cp genpwn /usr/bin/
sudo cp crun /usr/bin/
sudo cp subl /usr/bin/
sudo cp ida /usr/bin/
sudo cp ida64 /usr/bin/
source ~/.zshrc

echo "[*] Install GEF & Setup ~/.gdbinit"
bash -c "$(wget https://gef.blah.cat/sh -O -)"
echo set disassembly-flavor intel >> ~/.gdbinit

echo "[*] Install docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install docker.io -y
sudo apt-get install docker-compose-plugin -y
sudo docker --version
docker compose version

echo "[*] Installation complete! All tools, plugins, and configurations have been set up."
