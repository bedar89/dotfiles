# ENVIRONMENT CONFIGURATION

# Expand the history size
export HISTFILESIZE=10000
export HISTSIZE=500

# Don't put duplicate lines in the history and do not add lines that start with a space
export HISTCONTROL=erasedups:ignoredups:ignorespace

# Set Default Editor (change 'Nano' to the editor of your choice)
export EDITOR=/usr/bin/nano

# alias to show the date
alias da='date "+%Y-%m-%d %A %T %Z"'

# Alias's to modified commands
alias cp='cp -iv'
alias mv='mv -iv'
alias rm='rm -iv'
alias mkdir='mkdir -pv'
alias ps='ps auxf'
alias ping='ping -c 10'
alias ps='ps auxf'
alias ping='ping -c 10'

# Change directory aliases
cd() {
	builtin cd "$@"
	ll
}                                # Always list directory contents upon 'cd'
alias cd..='cd ../'              # Go back 1 directory level (for fast typers)
alias ..='cd ../'                # Go back 1 directory level
alias ...='cd ../../'            # Go back 2 directory levels
alias .3='cd ../../../'          # Go back 3 directory levels
alias .4='cd ../../../../'       # Go back 4 directory levels
alias .5='cd ../../../../../'    # Go back 5 directory levels
alias .6='cd ../../../../../../' # Go back 6 directory levels
alias -- -='cd -'

# Remove a directory and all files
alias rmd='/bin/rm  --recursive --force --verbose '

# Alias's for multiple directory listing commands
alias la='ls -Alh' # show hidden files
#alias ls='ls -aFh --color=always' # add colors and file type extensions
alias lx='ls -lXBh'      # sort by extension
alias lk='ls -lSrh'      # sort by size
alias lc='ls -lcrh'      # sort by change time
alias lu='ls -lurh'      # sort by access time
alias lr='ls -lRh'       # recursive ls
alias lt='ls -ltrh'      # sort by date
alias lm='ls -alh |more' # pipe through 'more'
alias lw='ls -xAh'       # wide listing format
#alias ll='ls -Fls' # long listing format
alias labc='ls -lap'             #alphabetical sort
alias lf="ls -l | egrep -v '^d'" # files only
alias ldir="ls -l | egrep '^d'"  # directories only

alias ls="exa --icons --group-directories-first"
alias ll="exa --icons --group-directories-first -a"

# alias chmod commands
alias mx='chmod a+x'
alias 000='chmod -R 000'
alias 644='chmod -R 644'
alias 666='chmod -R 666'
alias 755='chmod -R 755'
alias 777='chmod -R 777'

# Search command line history
alias h="history | grep "

# Search running processes
alias p="ps aux | grep "
alias topcpu="/bin/ps -eo pcpu,pid,user,args | sort -k 1 -r | head -10"

# Search files in the current folder
alias f="find . | grep "

# Count all files (recursively) in the current folder
alias countfiles="for t in files links directories; do echo \`find . -type \${t:0:1} | wc -l\` \$t; done 2> /dev/null"

# To see if a command is aliased, a file, or a built-in command
alias checkcommand="type -t"

# Show current network connections to the server
alias ipview="netstat -anpl | grep :80 | awk {'print \$5'} | cut -d\":\" -f1 | sort | uniq -c | sort -n | sed -e 's/^ *//' -e 's/ *\$//'"

# Show open ports
alias openports='netstat -nape --inet'

# Alias's for safe and forced reboots
alias rebootsafe='sudo shutdown -r now'
alias rebootforce='sudo shutdown -r -n now'

# Alias's to show disk space and space used in a folder
alias diskspace="du -S | sort -n -r |more"
alias folders='du -h --max-depth=1'
alias folderssort='find . -maxdepth 1 -type d -print0 | xargs -0 du -sk | sort -rn'
alias tree='tree -CAhF --dirsfirst'
alias treed='tree -CAFd'
alias mountedinfo='df -hT'

# Alias's for archives
alias mktar='tar -cvf'
alias mkbz2='tar -cvjf'
alias mkgz='tar -cvzf'
alias untar='tar -xvf'
alias unbz2='tar -xvjf'
alias ungz='tar -xvzf'

# Show all logs in /var/log
alias logs="sudo find /var/log -type f -exec file {} \; | grep 'text' | cut -d' ' -f1 | sed -e's/:$//g' | grep -v '[0-9]$' | xargs tail -f"

# SHA1
alias sha1='openssl sha1'

alias edit='code'                   # edit:         Opens any file in vscode
alias ~="cd ~"                      # ~:            Go Home
alias c='clear'                     # c:            Clear terminal display
mcd() { mkdir -p "$1" && cd "$1"; } # mcd:          Makes new Dir and jumps inside

#######################################################
# SPECIAL FUNCTIONS
#######################################################

# Extracts any archive(s) (if unp isn't installed)
extract() {
	for archive in $*; do
		if [ -f $archive ]; then
			case $archive in
			*.tar.bz2) tar xvjf $archive ;;
			*.tar.gz) tar xvzf $archive ;;
			*.bz2) bunzip2 $archive ;;
			*.rar) rar x $archive ;;
			*.gz) gunzip $archive ;;
			*.tar) tar xvf $archive ;;
			*.tbz2) tar xvjf $archive ;;
			*.tgz) tar xvzf $archive ;;
			*.zip) unzip $archive ;;
			*.Z) uncompress $archive ;;
			*.7z) 7z x $archive ;;
			*) echo "don't know how to extract '$archive'..." ;;
			esac
		else
			echo "'$archive' is not a valid file!"
		fi
	done
}

# Searches for text in all files in the current folder
ftext() {
	# -i case-insensitive
	# -I ignore binary files
	# -H causes filename to be printed
	# -r recursive search
	# -n causes line number to be printed
	# optional: -F treat search term as a literal, not a regular expression
	# optional: -l only print filenames and not the matching lines ex. grep -irl "$1" *
	grep -iIHrn --color=always "$1" . | less -r
}

# Copy file with a progress bar
cpp() {
	set -e
	strace -q -ewrite cp -- "${1}" "${2}" 2>&1 |
		awk '{
	count += $NF
	if (count % 10 == 0) {
		percent = count / total_size * 100
		printf "%3d%% [", percent
		for (i=0;i<=percent;i++)
			printf "="
			printf ">"
			for (i=percent;i<100;i++)
				printf " "
				printf "]\r"
			}
		}
	END { print "" }' total_size=$(stat -c '%s' "${1}") count=0
}

# Copy and go to the directory
cpg() {
	if [ -d "$2" ]; then
		cp $1 $2 && cd $2
	else
		cp $1 $2
	fi
}

# Move and go to the directory
mvg() {
	if [ -d "$2" ]; then
		mv $1 $2 && cd $2
	else
		mv $1 $2
	fi
}

# Create and go to the directory
mkdirg() {
	mkdir -p $1
	cd $1
}

# Goes up a specified number of directories  (i.e. up 4)
up() {
	local d=""
	limit=$1
	for ((i = 1; i <= limit; i++)); do
		d=$d/..
	done
	d=$(echo $d | sed 's/^\///')
	if [ -z "$d" ]; then
		d=..
	fi
	cd $d
}

# Show the current distribution
distribution() {
	local dtype
	# Assume unknown
	dtype="unknown"

	# First test against Fedora / RHEL / CentOS / generic Redhat derivative
	if [ -r /etc/rc.d/init.d/functions ]; then
		source /etc/rc.d/init.d/functions
		[ zz$(type -t passed 2>/dev/null) == "zzfunction" ] && dtype="redhat"

	# Then test against SUSE (must be after Redhat,
	# I've seen rc.status on Ubuntu I think? TODO: Recheck that)
	elif [ -r /etc/rc.status ]; then
		source /etc/rc.status
		[ zz$(type -t rc_reset 2>/dev/null) == "zzfunction" ] && dtype="suse"

	# Then test against Debian, Ubuntu and friends
	elif [ -r /lib/lsb/init-functions ]; then
		source /lib/lsb/init-functions
		[ zz$(type -t log_begin_msg 2>/dev/null) == "zzfunction" ] && dtype="debian"

	# Then test against Gentoo
	elif [ -r /etc/init.d/functions.sh ]; then
		source /etc/init.d/functions.sh
		[ zz$(type -t ebegin 2>/dev/null) == "zzfunction" ] && dtype="gentoo"

	# For Mandriva we currently just test if /etc/mandriva-release exists
	# and isn't empty (TODO: Find a better way :)
	elif [ -s /etc/mandriva-release ]; then
		dtype="mandriva"

	# For Slackware we currently just test if /etc/slackware-version exists
	elif [ -s /etc/slackware-version ]; then
		dtype="slackware"

	fi
	echo $dtype
}

# Show the current version of the operating system
ver() {
	local dtype
	dtype=$(distribution)

	if [ $dtype == "redhat" ]; then
		if [ -s /etc/redhat-release ]; then
			cat /etc/redhat-release && uname -a
		else
			cat /etc/issue && uname -a
		fi
	elif [ $dtype == "suse" ]; then
		cat /etc/SuSE-release
	elif [ $dtype == "debian" ]; then
		lsb_release -a
		# sudo cat /etc/issue && sudo cat /etc/issue.net && sudo cat /etc/lsb_release && sudo cat /etc/os-release # Linux Mint option 2
	elif [ $dtype == "gentoo" ]; then
		cat /etc/gentoo-release
	elif [ $dtype == "mandriva" ]; then
		cat /etc/mandriva-release
	elif [ $dtype == "slackware" ]; then
		cat /etc/slackware-version
	else
		if [ -s /etc/issue ]; then
			cat /etc/issue
		else
			echo "Error: Unknown distribution"
			exit 1
		fi
	fi
}

# Show current network information
netinfo() {
    # Define colors
    readonly GREEN="\033[0;32m"
    readonly YELLOW="\033[0;33m"
    readonly NC="\033[0m" # No Color

    # ASCII art outline
    readonly OUTLINE="-----------------------------------------------------"

    echo -e "${GREEN}+---------------- Network Information ----------------+${NC}"

    main_interface=$(ip route | grep default | awk '{print $5}')
    ipv4_address=$(ip -4 addr show dev "$main_interface" | awk '/inet / {print $2}')
    netmask=$(ip -4 addr show dev "$main_interface" | awk '/inet / {print $3}')
    mac_address=$(ip link show dev "$main_interface" | awk '/ether/ {print $2}')
    
    echo -e "${YELLOW}Interface:${NC} $main_interface"
    echo -e "${YELLOW}IPv4 Address:${NC} $ipv4_address"
    echo -e "${YELLOW}Netmask:${NC} $netmask"
    echo -e "${YELLOW}MAC Address:${NC} $mac_address"

    # Display DNS IP Addresses received via DHCP
    echo -e "\n${YELLOW}DNS IP Addresses (via DHCP):${NC}"
    nmcli dev show "$main_interface" | awk '/IP4.DNS/ {print "  " $2}'
    
    echo -e "${GREEN}+$OUTLINE+${NC}"
}






# IP address lookup
alias whatismyip="whatsmyip"
function whatsmyip() {
	# Internal IP Lookup
	local internal_ip=$(ip -4 addr show dev "$(ip route | grep default | awk '{print $5}')" | awk '/inet / {print $2}')
	echo "Internal IP: $internal_ip"

	# External IP Lookup
	local external_ip=$(curl -s ifconfig.me)
	echo "External IP: $external_ip"
}

#######################################################
# Set the ultimate amazing command prompt
#######################################################

alias cpu="grep 'cpu ' /proc/stat | awk '{usage=(\$2+\$4)*100/(\$2+\$4+\$5)} END {print usage}' | awk '{printf(\"%.1f\n\", \$1)}'"
function __setprompt {
	local LAST_COMMAND=$? # Must come first!

	# Define colors
	local LIGHTGRAY="\033[0;37m"
	local WHITE="\033[1;37m"
	local BLACK="\033[0;30m"
	local DARKGRAY="\033[1;30m"
	local RED="\033[0;31m"
	local LIGHTRED="\033[1;31m"
	local GREEN="\033[0;32m"
	local LIGHTGREEN="\033[1;32m"
	local BROWN="\033[0;33m"
	local YELLOW="\033[1;33m"
	local BLUE="\033[0;34m"
	local LIGHTBLUE="\033[1;34m"
	local MAGENTA="\033[0;35m"
	local LIGHTMAGENTA="\033[1;35m"
	local CYAN="\033[0;36m"
	local LIGHTCYAN="\033[1;36m"
	local NOCOLOR="\033[0m"

	# Show error exit code if there is one
	if [[ $LAST_COMMAND != 0 ]]; then
		# PS1="\[${RED}\](\[${LIGHTRED}\]ERROR\[${RED}\])-(\[${LIGHTRED}\]Exit Code \[${WHITE}\]${LAST_COMMAND}\[${RED}\])-(\[${LIGHTRED}\]"
		PS1="\[${DARKGRAY}\](\[${LIGHTRED}\]ERROR\[${DARKGRAY}\])-(\[${RED}\]Exit Code \[${LIGHTRED}\]${LAST_COMMAND}\[${DARKGRAY}\])-(\[${RED}\]"
		if [[ $LAST_COMMAND == 1 ]]; then
			PS1+="General error"
		elif [ $LAST_COMMAND == 2 ]; then
			PS1+="Missing keyword, command, or permission problem"
		elif [ $LAST_COMMAND == 126 ]; then
			PS1+="Permission problem or command is not an executable"
		elif [ $LAST_COMMAND == 127 ]; then
			PS1+="Command not found"
		elif [ $LAST_COMMAND == 128 ]; then
			PS1+="Invalid argument to exit"
		elif [ $LAST_COMMAND == 129 ]; then
			PS1+="Fatal error signal 1"
		elif [ $LAST_COMMAND == 130 ]; then
			PS1+="Script terminated by Control-C"
		elif [ $LAST_COMMAND == 131 ]; then
			PS1+="Fatal error signal 3"
		elif [ $LAST_COMMAND == 132 ]; then
			PS1+="Fatal error signal 4"
		elif [ $LAST_COMMAND == 133 ]; then
			PS1+="Fatal error signal 5"
		elif [ $LAST_COMMAND == 134 ]; then
			PS1+="Fatal error signal 6"
		elif [ $LAST_COMMAND == 135 ]; then
			PS1+="Fatal error signal 7"
		elif [ $LAST_COMMAND == 136 ]; then
			PS1+="Fatal error signal 8"
		elif [ $LAST_COMMAND == 137 ]; then
			PS1+="Fatal error signal 9"
		elif [ $LAST_COMMAND -gt 255 ]; then
			PS1+="Exit status out of range"
		else
			PS1+="Unknown error code"
		fi
		PS1+="\[${DARKGRAY}\])\[${NOCOLOR}\]\n"
	else
		PS1=""
	fi

	# Date
	PS1+="\[${DARKGRAY}\](\[${CYAN}\]\$(date +%a) $(date +%b-'%-m')" # Date
	PS1+="${BLUE} $(date +'%-I':%M:%S%P)\[${DARKGRAY}\])-"           # Time

	# CPU
	PS1+="(\[${MAGENTA}\]CPU $(cpu)%"

	# Jobs
	PS1+="\[${DARKGRAY}\]:\[${MAGENTA}\]\j"

	# Network Connections (for a server - comment out for non-server)
	PS1+="\[${DARKGRAY}\]:\[${MAGENTA}\]Net $(awk 'END {print NR}' /proc/net/tcp)"

	PS1+="\[${DARKGRAY}\])-"

	# User and server
	local SSH_IP=$(echo $SSH_CLIENT | awk '{ print $1 }')
	local SSH2_IP=$(echo $SSH2_CLIENT | awk '{ print $1 }')
	if [ $SSH2_IP ] || [ $SSH_IP ]; then
		PS1+="(\[${RED}\]\u@\h"
	else
		PS1+="(\[${RED}\]\u"
	fi

	# Current directory
	PS1+="\[${DARKGRAY}\]:\[${BROWN}\]\w\[${DARKGRAY}\])-"

	# Total size of files in current directory
	PS1+="(\[${GREEN}\]$(/bin/ls -lah | /bin/grep -m 1 total | /bin/sed 's/total //')\[${DARKGRAY}\]:"

	# Number of files
	PS1+="\[${GREEN}\]\$(/bin/ls -A -1 | /usr/bin/wc -l)\[${DARKGRAY}\])"

	# Skip to the next line
	PS1+="\n"

	if [[ $EUID -ne 0 ]]; then
		PS1+="\[${GREEN}\]>\[${NOCOLOR}\] " # Normal user
	else
		PS1+="\[${RED}\]>\[${NOCOLOR}\] " # Root user
	fi

	# PS2 is used to continue a command using the \ character
	PS2="\[${DARKGRAY}\]>\[${NOCOLOR}\] "

	# PS3 is used to enter a number choice in a script
	PS3='Please enter a number from above list: '

	# PS4 is used for tracing a script in debug mode
	PS4='\[${DARKGRAY}\]+\[${NOCOLOR}\] '
}
PROMPT_COMMAND='__setprompt'

alias k="kubectl"
alias tf="terraform"
alias a="ansible"
alias ap="ansible-playbook"

alias g="goto"

cd() {
	builtin cd "$@"
	ll
}

# Define colors
readonly GREEN="\033[0;32m"
readonly YELLOW="\033[0;33m"
readonly BLUE="\033[0;34m"
readonly PURPLE="\033[0;35m"
readonly RED="\033[0;31m"
readonly NC="\033[0m" # No Color

# ASCII art outline
readonly OUTLINE="-----------------------------------------------------"
readonly HEADER="
-----------------------------------------------------
          ${YELLOW}Update Script for Linux${NC}
-----------------------------------------------------
"

# Update function
update() {
    local do_apt=true
    local do_flatpak=true
    local do_snap=true
    local do_nala=false
    local full_upgrade=false

    # Parse optional parameters
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f)
                full_upgrade=true
                shift
                ;;
            -n)
                do_apt=false
                do_nala=true
                shift
                ;;
            -i)
                shift
                while [[ $# -gt 0 && "$1" != -* ]]; do
                    case "$1" in
                        apt)
                            do_apt=true
                            ;;
                        flatpak)
                            do_flatpak=true
                            ;;
                        snap)
                            do_snap=true
                            ;;
                    esac
                    shift
                done
                ;;
            -e)
                shift
                while [[ $# -gt 0 && "$1" != -* ]]; do
                    case "$1" in
                        apt)
                            do_apt=false
                            ;;
                        flatpak)
                            do_flatpak=false
                            ;;
                        snap)
                            do_snap=false
                            ;;
                    esac
                    shift
                done
                ;;
            *)
                echo "Invalid option: $1"
                return 1
                ;;
        esac
    done

    # Function to update Apt or Nala package manager
    update_package_manager() {
        local package_manager=$1
        local package_manager_name=$2
        if $package_manager; then
            if [[ "$package_manager_name" == "apt" ]]; then
                echo -e "${GREEN}Updating $package_manager_name...${NC}"
                sudo apt update
                if $full_upgrade; then
                    echo -e "${GREEN}Performing full-upgrade for $package_manager_name...${NC}"
                    sudo apt full-upgrade -y
                fi
            elif [[ "$package_manager_name" == "flatpak" ]]; then
                echo -e "${YELLOW}Updating $package_manager_name...${NC}"
                flatpak update -y
            elif [[ "$package_manager_name" == "snap" ]]; then
                echo -e "${BLUE}Updating $package_manager_name...${NC}"
                sudo snap refresh
            elif [[ "$package_manager_name" == "nala" ]]; then
                echo -e "${PURPLE}Updating $package_manager_name...${NC}"
                sudo nala update
                if $full_upgrade; then
                    echo -e "${PURPLE}Performing full-upgrade for $package_manager_name...${NC}"
                    sudo nala upgrade
                fi
            fi
        else
            echo -e "${PURPLE}$package_manager_name updates excluded.${NC}"
        fi
    }

    # Output progress messages and summary
    echo -e "${HEADER}"

    echo -e "${YELLOW}---------------- Running Updates ----------------${NC}"

    update_package_manager "$do_apt" "apt"
    update_package_manager "$do_flatpak" "flatpak"
    update_package_manager "$do_snap" "snap"
    update_package_manager "$do_nala" "nala"

    echo -e "${YELLOW}-----------------------------------------------${NC}"
    echo -e "${GREEN}Updates successfully completed:${NC}"
    local updates_completed=false
    if $do_apt; then
        if $full_upgrade; then
            echo -e " - ${GREEN}apt (full-upgrade)${NC}"
            updates_completed=true
        elif [[ "$do_flatpak" == "false" && "$do_snap" == "false" && "$do_nala" == "false" ]]; then
            echo -e " - ${GREEN}apt${NC}"
            updates_completed=true
        fi
    fi
    if $do_flatpak; then
        echo -e " - ${YELLOW}flatpak${NC}"
        updates_completed=true
    fi
    if $do_snap; then
        echo -e " - ${BLUE}snap${NC}"
        updates_completed=true
    fi
    if $do_nala; then
        echo -e " - ${PURPLE}nala${NC}"
        updates_completed=true
    fi

    if ! $updates_completed; then
        echo -e "${RED}No package managers were specified for update.${NC}"
    fi

    echo -e "${GREEN}-----------------------------------------------${NC}"
}

# Create the alias
alias update="update"


# Example usage:
# To update using apt (update):
# update
#
# To update using nala (updaten):
# updaten
#
# To update everything except flatpak and snap using update:
# update -r flatpak -r snap
#
# To update only snap and apt using updaten:
# updaten snap apt



# # docker
# alias dps="docker ps"
# alias dexec='docker exec -it docker_php_1'
# alias dpull='docker pull'

# # docker-compose
# alias dcps='docker-compose ps'
# alias dcstart='docker-compose start'
# alias dcstop='docker-compose stop'
# alias dcrestart='docker-compose restart'
# alias dcup='docker-compose up -d'

# git
alias gs="git status -s"
alias gl="git log"
alias gll="git log --pretty=format:\"%C(yellow)%h\\\\ %ad%Cred%d\\\\ %Creset%s%Cblue\\\\ [%cn]\" --decorate --date=short"
alias gc="git commit -m"
alias ga="git add ."
alias gp="git push --all && git push --tags"
alias gclear="git reset --hard && git clean -df"
alias gb="git branch"

############################################################################
#                                                                          #
#               ------- Useful Docker Aliases --------                     #
#                                                                          #
#     # Installation :                                                     #
#     copy/paste these lines into your .bashrc or .zshrc file or just      #
#     type the following in your current shell to try it out:              #
#                                                                          #
#     # Usage:                                                             #
#     daws <svc> <cmd> <opts> : aws cli in docker with <svc> <cmd> <opts>  #
#     dc             : docker compose                                      #
#     dcu            : docker compose up -d                                #
#     dcd            : docker compose down                                 #
#     dcr            : docker compose run                                  #
#     dex <container>: execute a bash shell inside the RUNNING <container> #
#     di <container> : docker inspect <container>                          #
#     dim            : docker images                                       #
#     dip            : IP addresses of all running containers              #
#     dl <container> : docker logs -f <container>                          #
#     dnames         : names of all running containers                     #
#     dps            : docker ps                                           #
#     dpsa           : docker ps -a                                        #
#     drmc           : remove all exited containers                        #
#     drmid          : remove all dangling images                          #
#     drun <image>   : execute a bash shell in NEW container from <image>  #
#     dsr <container>: stop then remove <container>                        #
#                                                                          #
############################################################################

function dnames-fn {
	for ID in $(docker ps | awk '{print $1}' | grep -v 'CONTAINER' | docker-color-output); do
		docker inspect $ID | grep Name | head -1 | awk '{print $2}' | sed 's/,//g' | sed 's%/%%g' | sed 's/"//g'
	done
}

function dip-fn {
	echo "IP addresses of all named running containers"

	for DOC in $(dnames-fn); do
		IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$DOC")
		OUT+=$DOC'\t'$IP'\n'
	done
	echo -e $OUT | column -t
	unset OUT
}

function dex-fn {
	docker exec -it $1 ${2:-bash}
}

function di-fn {
	docker inspect $1
}

function dl-fn {
	docker logs -f $1
}

function drun-fn {
	docker run -it $1 $2
}

function dcr-fn {
	docker compose run $@ 
}

function dsr-fn {
	docker stop $1
	docker rm $1
}

function drmc-fn {
	docker rm $(docker ps --all -q -f status=exited)
}

function drmid-fn {
	imgs=$(docker images -q -f dangling=true)
	[ ! -z "$imgs" ] && docker rmi "$imgs" || echo "no dangling images."
}

# in order to do things like dex $(dlab label) sh
function dlab {
	docker ps --filter="label=$1" --format="{{.ID}}" | docker-color-output
}

function dc-fn {
	docker compose $*
}

function d-aws-cli-fn {
	docker run \
		-e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
		-e AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION \
		-e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
		amazon/aws-cli:latest $1 $2 $3
}

alias daws=d-aws-cli-fn
alias dc=dc-fn
alias dcu="docker compose up -d"
alias dcd="docker compose down"
alias dcr=dcr-fn
alias dex=dex-fn
alias di=di-fn
alias dim="docker images | docker-color-output"
alias dip=dip-fn
alias dl=dl-fn
alias dnames=dnames-fn
alias dps="docker ps | docker-color-output"
alias dpsa="docker ps -a | docker-color-output"
alias drmc=drmc-fn
alias drmid=drmid-fn
alias drun=drun-fn
alias dsp="docker system prune --all"
alias dsr=dsr-fn

# dotfiles repo
alias config='/usr/bin/git --git-dir=$HOME/.cfg/ --work-tree=$HOME'
