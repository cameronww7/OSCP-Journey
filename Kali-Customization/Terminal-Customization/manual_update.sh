#!/usr/bin/env zsh


# Note
# ---------------------------------------
# Make sure file has needed perms
# chmod +x terminal_setup.sh


# Install Oh-My_ZSH
# ---------------------------------------
# Install oh-my-zsh
sudo curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh | sh; zsh


# Install Plugins
# ---------------------------------------
# add highlighting
sudo git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $HOME/.oh-my-zsh/plugins/zsh-syntax-highlighting

# add auto-suggester
sudo git clone https://github.com/zsh-users/zsh-autosuggestions $HOME/.oh-my-zsh/plugins/zsh-autosuggestions

# install powerlevel9k
sudo git clone https://github.com/bhilburn/powerlevel9k.git $HOME/.oh-my-zsh/custom/themes/powerlevel9k

# install k
sudo git clone https://github.com/supercrabtree/k $HOME/.oh-my-zsh/plugins/k


# Install .zshrc file 
# ---------------------------------------
# sudo git clone https://github.com/cameronww7/path to zshrc