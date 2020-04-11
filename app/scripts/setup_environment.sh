set -e

# echo "Installing pip packages..."
# pip install -r requirements.txt

echo "export PATH=\$PATH:\$HOME/.local/bin" >> /home/$USERNAME/.zshrc
chown $USER_UID:$USER_GID /home/$USERNAME/.zshrc

echo "Download Oh My Zsh Installer..."
curl -Lo install.sh https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh
echo "Run Oh My Zsh Installer..."
zsh install.sh
echo "Remove Oh My Zsh Installer..."
rm install.sh

echo "Add Oh My Zsh plugins..."
echo "\t zsh-autosuggestions"
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
sed -i 's/plugins=(git)/plugins=(git zsh-autosuggestions)/g' ~/.zshrc
echo "\t zsh-autosuggestions [DONE]"
