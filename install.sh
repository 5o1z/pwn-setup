#!/bin/bash
set -euo pipefail

# ==================== Color Configuration & Effects ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

animate_text() {
    local text="$1"
    echo -ne "${CYAN}"
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep 0.015
    done
    echo -e "${NC}"
}

show_spinner() {
    local pid=$!
    local delay=0.1
    local spin_chars='⣾⣽⣻⢿⡿⣟⣯⣷'
    while ps -p $pid > /dev/null; do
        for ((i=0; i<${#spin_chars}; i++)); do
            echo -ne "\r[${spin_chars:$i:1}]"
            sleep $delay
        done
    done
    echo -ne "\r\033[K"
}

# ==================== System Configuration ====================
animate_text "[*] Adding i386 architecture and updating packages..."
sudo dpkg --add-architecture i386
sudo apt-get update -y > /dev/null 2>&1 & show_spinner

# ==================== Main Package Installation ====================
animate_text "[*] Installing essential packages..."
sudo apt-get install -y --no-install-recommends \
    libc6:i386 libc6-dbg:i386 libc6-dbg \
    libffi-dev libssl-dev liblzma-dev \
    ipython3 net-tools python3-dev python3-pip \
    build-essential ruby ruby-dev strace ltrace \
    binwalk nasm wget gdb gdb-multiarch netcat \
    git zsh patchelf file python3-distutils zstd \
    ripgrep python-is-python3 tzdata \
    docker.io docker-compose-plugin > /dev/null 2>&1 & show_spinner

# ==================== Cleanup ====================
animate_text "[*] Cleaning apt cache..."
sudo apt-get autoremove -y > /dev/null 2>&1
sudo apt-get clean > /dev/null 2>&1
sudo rm -rf /var/lib/apt/lists/* > /dev/null 2>&1

# ==================== Oh My Zsh Installation ====================
animate_text "[*] Installing Oh My Zsh..."
RUNZSH=no CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended > /dev/null 2>&1 & show_spinner

# ==================== Zsh Plugin Configuration ====================
animate_text "[*] Configuring Zsh plugins..."
ZSH_PLUGINS_DIR="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins"

clone_plugin() {
    if [ ! -d "$ZSH_PLUGINS_DIR/$1" ]; then
        git clone --depth 1 "$2" "$ZSH_PLUGINS_DIR/$1" > /dev/null 2>&1 & show_spinner
    fi
}

clone_plugin "zsh-autosuggestions" "https://github.com/zsh-users/zsh-autosuggestions"
clone_plugin "zsh-completions" "https://github.com/zsh-users/zsh-completions"
clone_plugin "zsh-syntax-highlighting" "https://github.com/zsh-users/zsh-syntax-highlighting"

# Update .zshrc
sed -i '/^plugins=/c\plugins=(git zsh-autosuggestions zsh-completions zsh-syntax-highlighting)' ~/.zshrc

# ==================== Ruby & Python Setup ====================
animate_text "[*] Installing Ruby gems..."
sudo gem install -N one_gadget seccomp-tools > /dev/null 2>&1 & show_spinner

animate_text "[*] Upgrading pip and installing pwntools..."
python3 -m pip install -U pip wheel > /dev/null 2>&1
python3 -m pip install --no-cache-dir pwntools > /dev/null 2>&1 & show_spinner

# ==================== GDB Configuration ====================
animate_text "[*] Configuring GDB..."
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/sh
echo "source ~/.gdbinit-gef.py" > ~/.gdbinit
echo "set disassembly-flavor intel" >> ~/.gdbinit

# ==================== Docker Setup ====================
if ! command -v docker &> /dev/null; then
    animate_text "[*] Installing Docker..."
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -y > /dev/null 2>&1 & show_spinner
    sudo apt-get install -y docker.io docker-compose-plugin > /dev/null 2>&1 & show_spinner
fi

# ==================== Final Configuration ====================
animate_text "[*] Finalizing setup..."

# Install custom tools
for tool in crun genpwn ida ida64 subl; do
    if [ -f "$tool" ]; then
        echo -e "${GREEN}[+]${NC} Installing ${YELLOW}$tool${NC}..."
        chmod +x "$tool"
        sudo mv "$tool" /usr/bin/
    else
        echo -e "${RED}[-]${NC} ${YELLOW}$tool${NC} not found in current directory"
    fi
done

# Apply configurations
echo -ne "${BLUE}Applying final configurations...${NC}"
source ~/.zshrc >/dev/null 2>&1
echo -e "\r${GREEN}✓${NC} Configurations applied successfully"

# ==================== Completion Art ====================
echo -e "\n${GREEN}"
printf " %s\n" "███████╗███████╗███████╗███████╗" "██╔════╝██╔════╝██╔════╝██╔════╝" "█████╗  █████╗  ███████╗███████╗" "██╔══╝  ██╔══╝  ╚════██║╚════██║" "██║     ███████╗███████║███████║" "╚═╝     ╚══════╝╚══════╝╚══════╝"
echo -e "${NC}"
animate_text "[✅] Installation complete! All tools and configurations are ready."
