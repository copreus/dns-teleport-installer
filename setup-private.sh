#!/bin/bash


G='\033[0;32m'
Y='\033[1;33m'
R='\033[0;31m'
C='\033[0;36m'
N='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${R}Error: Must run as root.${N}"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/installdir.txt"

if [ -f "$CONFIG_FILE" ]; then
    BASE_DIR=$(cat "$CONFIG_FILE")
    if [ ! -d "$BASE_DIR" ]; then
        echo -e "${Y}Saved directory not found.${N}"
        read -p "Enter installation directory [Default: /root]: " USER_DIR
        BASE_DIR=${USER_DIR:-/root}
    fi
else
    read -p "Enter installation directory [Default: /root]: " USER_DIR
    BASE_DIR=${USER_DIR:-/root}
fi

BASE_DIR=${BASE_DIR%/}
echo "$BASE_DIR" > "$CONFIG_FILE"

pause() {
    echo -e "${Y}... processing ...${N}"
    sleep 0.5
}

is_port_free() {
    if ss -tuln | grep -q ":$1 "; then return 1; else return 0; fi
}

get_valid_port() {
    local PROMPT=$1
    while true; do
        read -p "$PROMPT" PORT
        [ -z "$PORT" ] && PORT=$(shuf -i 2000-60000 -n 1)
        if is_port_free "$PORT"; then echo "$PORT"; return; else echo -e "${R}Port $PORT busy.${N}" >&2; fi
    done
}

get_input() {
    local PROMPT=$1
    local VAL=""
    while [ -z "$VAL" ]; do read -p "$PROMPT" VAL; done
    echo "$VAL"
}

get_lane_name_by_port() {
    grep -l "sni://:$1" /etc/systemd/system/gost-*.service 2>/dev/null | while read f; do
        basename "$f" | sed 's/gost-//;s/.service//'
    done
}

setup_base() {
    echo -e "${G}>>> SYSTEM SETUP (Plain DNS + Docker Friendly) <<<${N}"
    

    if dpkg -s iptables-persistent >/dev/null 2>&1; then
        echo -e "${Y}Removing conflicting iptables-persistent...${N}"
        apt-get remove -y iptables-persistent netfilter-persistent
    fi
    
    echo "Configuring system DNS..."
    systemctl disable --now systemd-resolved 2>/dev/null
    rm -rf /etc/resolv.conf
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    pause

    echo "Installing dependencies..."
    apt-get update -q
    apt-get install -y curl nano ufw dnsmasq nginx libnginx-mod-stream net-tools nload unzip gzip wget python3-bcrypt dnsutils
    pause

    if ! command -v docker &> /dev/null; then
        echo "Installing Docker..."
        curl -sSL https://get.docker.com/ | CHANNEL=stable bash
    fi

    if ! command -v gost &> /dev/null; then
        echo "Fetching GOST..."
        wget -q https://github.com/ginuerzh/gost/releases/download/v2.11.5/gost-linux-amd64-2.11.5.gz
        gunzip gost-linux-amd64-2.11.5.gz
        mv gost-linux-amd64-2.11.5 /usr/local/bin/gost
        chmod +x /usr/local/bin/gost
        rm -f gost-linux-amd64-2.11.5.gz
    fi

    echo ""
    echo -e "${C}--- Configuration ---${N}"
    
    VPS_IP=$(curl -4 -s https://checkip.amazonaws.com/)
    
    # Find the "Magic IP" (Docker Bridge Gateway)
    # This scans your routing table for the bridge network (like 10.42.42.1)
    DOCKER_GW=$(ip route | grep -v default | grep "src" | grep -E "10\.|172\." | awk '{print $9}' | head -n1)
    [ -z "$DOCKER_GW" ] && DOCKER_GW="172.17.0.1"
    
    echo -e "Detected Public IP: ${G}$VPS_IP${N}"
    echo -e "Detected Internal Bridge IP: ${G}$DOCKER_GW${N}"

    # DNSMASQ for local resolution
    mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null
    cat <<EOF > /etc/dnsmasq.conf
listen-address=127.0.0.1
port=5353
bind-interfaces
no-resolv
no-hosts
address=/#/$VPS_IP
EOF
    systemctl restart dnsmasq
    systemctl enable dnsmasq

    # NGINX - Stream Routing for SmartDNS (SNI)
    rm /etc/nginx/nginx.conf 2>/dev/null
    cat <<EOF > /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

stream {
    resolver 1.1.1.1 ipv6=off;
    resolver_timeout 5s;
    tcp_nodelay on;
    proxy_socket_keepalive on;
    proxy_connect_timeout 15s;
    proxy_timeout 300s;

    map \$ssl_preread_server_name \$target_backend {
        default              \$ssl_preread_server_name:443;
    }

    server {
        listen 443;
        ssl_preread on;
        proxy_pass \$target_backend;
    }
}
EOF
    systemctl restart nginx
    systemctl enable nginx

    echo "Configuring AdGuard Home..."
    AGH_USER=$(get_input "Username: ")
    read -s -p "Password: " AGH_PASS
    echo ""
    
    HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'$AGH_PASS', bcrypt.gensalt()).decode())")

    mkdir -p "$BASE_DIR/dns-teleport/adguard/conf"
    mkdir -p "$BASE_DIR/dns-teleport/adguard/work"


    cat <<EOF > "$BASE_DIR/dns-teleport/adguard/conf/AdGuardHome.yaml"
http:
  pprof:
    port: 6060
    enabled: false
  address: "0.0.0.0:3000"
  session_ttl: 720h
users:
  - name: "$AGH_USER"
    password: "$HASH"
auth_attempts: 5
block_auth_min: 15
dns:
  bind_hosts:
    - "0.0.0.0"
  port: 53
  anonymize_client_ip: false
  upstream_dns:
    - 1.1.1.1
    - '# For now, the DNS will use the default address: 1.1.1.1'
    - '# If you want all websites to appear as if they are coming from your VPS IP,'
    - '# change the DNS to: 127.0.0.1:5353'
    - '# Use 127.0.0.1:5353 to route traffic through your VPS, your endpoints,'
    - '# or both at the same time.'
    - '# For example, if you want to route Netflix traffic, make sure to update'
    - '# your nginx configuration.'
    - '# Also add the domain here (Netflix is just an example):'
    - '# [/netflix.com/]127.0.0.1:5353'
    - '# Depending on your nginx setup, Netflix will see either:'
    - '# - your VPS IP, or'
    - '# - the IP of the VPN/proxy lane you added in Nginx.'
    - '# ALWAYS USE 127.0.0.1:5353 for routing. This setting never changes.'
  bootstrap_dns:
    - 1.1.1.1
  upstream_mode: load_balance
  allowed_clients:
    - "127.0.0.1"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "100.64.0.0/10"
tls:
  enabled: false
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
schema_version: 31
EOF

    cat <<EOF > "$BASE_DIR/dns-teleport/docker-compose.yml"
services:
  adguardhome:
    container_name: adguardhome
    image: adguard/adguardhome:latest
    restart: unless-stopped
    network_mode: "host"
    volumes:
      - ./adguard/conf:/opt/adguardhome/conf
      - ./adguard/work:/opt/adguardhome/work
    environment:
      - TZ=UTC
EOF

    cd "$BASE_DIR/dns-teleport"
    docker compose up -d >/dev/null 2>&1

    echo "Waiting 3 seconds for AdGuard to start..."
    sleep 3


    echo -e "${C}Configuring Firewall...${N}"
    
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming
    ufw default allow outgoing
    
    ufw allow 22/tcp       
    ufw allow 53           
    ufw allow 443/tcp      
    ufw allow 51820/udp    
    ufw allow 51821/tcp    

    echo "Allowing Private Subnets"
    ufw allow from 10.0.0.0/8 
    ufw allow from 172.16.0.0/12 
    ufw allow from 192.168.0.0/16 
    ufw allow from 100.64.0.0/10

    
    echo "y" | ufw enable >/dev/null

    echo -e "${G}Setup Complete.${N}"
    echo ""
    echo -e "${Y}--- IMPORTANT: HOW TO CONNECT ---${N}"
    echo "1. Connect to your VPN."
    echo "2. Open this URL: http://$DOCKER_GW:3000"
    echo "   (This is your Internal Docker Gateway IP)"
    echo "3. If that fails, try: http://172.17.0.1:3000"
    echo ""
    echo -e "${Y}--- DNS CONFIG ---${N}"
    echo "In your wireguard Client Config:"
    echo "DNS = $DOCKER_GW" 
}

setup_vpn() {
    echo -e "${G}>>> NEW VPN LANE (Gluetun) <<<${N}"
    
    CONN_NAME=$(get_input "Lane Name (e.g. la): ")
    INSTALL_PATH="$BASE_DIR/vpn-$CONN_NAME"
    
    PROXY_PORT=$(get_valid_port "Internal Proxy Port [Enter for random]: ")
    SNI_PORT=$(get_valid_port "SNI Listening Port [Enter for random]: ")
    
    mkdir -p "$INSTALL_PATH"

    cat <<EOF > "$INSTALL_PATH/docker-compose.yml"
services:
  gluetun:
    image: qmcgaw/gluetun
    container_name: vpn-$CONN_NAME
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    ports:
      - $PROXY_PORT:8888
    volumes:
      - ./wg0.conf:/gluetun/wireguard/wg0.conf:ro
    environment:
      - VPN_SERVICE_PROVIDER=custom
      - VPN_TYPE=wireguard
      - DOT=off
      - DNS_ADDRESS=1.1.1.1
      - HTTPPROXY=on
    restart: always
EOF

    cat <<EOF > "$INSTALL_PATH/wg0.conf"
# If your Wireguard config endpoint is a domain, GLUETUN WON'T WORK
# Ping the domain, then copy the IP. Replace the endpoint on the Wireguard config with the IP, and hope it works.
# See my pro photoshop skills for an example: https://i.vgy.me/D3ISSe.png
# Paste conf below. To save, "Ctrl+X", then "Y", then Enter

EOF

    cat <<EOF > "/etc/systemd/system/gost-$CONN_NAME.service"
[Unit]
Description=GOST Bridge $CONN_NAME
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L "sni://:$SNI_PORT" -F "http://127.0.0.1:$PROXY_PORT"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "gost-$CONN_NAME" >/dev/null 2>&1

    echo ""
    read -p "Route ALL traffic through this lane? (y/n): " ROUTE_ALL
    if [[ "$ROUTE_ALL" =~ ^[Yy]$ ]]; then
        sed -i 's/default.*;/default              127.0.0.1:'"$SNI_PORT"';/g' /etc/nginx/nginx.conf
        echo -e "${Y}Global traffic routed to $CONN_NAME.${N}"
    else
        ROUTE_DOMAIN=$(get_input "Enter a domain to route (e.g. ~.netflix.com): ")
        sed -i "/default/i \ \ \ \ \ \ \ \ $ROUTE_DOMAIN    127.0.0.1:$SNI_PORT;" /etc/nginx/nginx.conf
        echo "Added $ROUTE_DOMAIN"
    fi
    systemctl restart nginx

    echo -e "${Y}Opening config editor... Paste WireGuard conf now.${N}"
    read -p "Press Enter to open..."
    nano "$INSTALL_PATH/wg0.conf"

    cd "$INSTALL_PATH"
    docker compose up -d >/dev/null 2>&1
    echo -e "${G}Lane '$CONN_NAME' Active on Port $SNI_PORT${N}"
}

setup_proxy() {
    echo -e "${G}>>> NEW PROXY LANE <<<${N}"
    
    CONN_NAME=$(get_input "Lane Name (e.g. albania): ")
    SNI_PORT=$(get_valid_port "SNI Listening Port [Enter for random]: ")
    
    P_TYPE=$(get_input "Type (socks5 / http): ")
    P_IP=$(get_input "IP: ")
    P_PORT=$(get_input "Port: ")
    read -p "Username (Enter for IP Auth): " P_USER
    
    if [ -n "$P_USER" ]; then
        read -s -p "Password: " P_PASS
        echo ""
        PROXY_STRING="$P_TYPE://$P_USER:$P_PASS@$P_IP:$P_PORT"
    else
        PROXY_STRING="$P_TYPE://$P_IP:$P_PORT"
    fi

    cat <<EOF > "/etc/systemd/system/gost-$CONN_NAME.service"
[Unit]
Description=GOST Bridge $CONN_NAME
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L "sni://:$SNI_PORT" -F "$PROXY_STRING"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "gost-$CONN_NAME" >/dev/null 2>&1

    ROUTE_DOMAIN=$(get_input "Domain to route (e.g. ~.youtube.com): ")
    sed -i "/default/i \ \ \ \ \ \ \ \ $ROUTE_DOMAIN    127.0.0.1:$SNI_PORT;" /etc/nginx/nginx.conf
    systemctl restart nginx

    echo -e "${G}Lane '$CONN_NAME' Active on Port $SNI_PORT${N}"
}

manage_routing() {
    echo -e "${C}--- Traffic Routing ---${N}"
    NGINX="/etc/nginx/nginx.conf"
    
    DEFAULT_LINE=$(grep "default" $NGINX)
    
    if [[ "$DEFAULT_LINE" == *"\$ssl_preread_server_name:443;"* ]]; then
        STATE="${Y}VPS Direct (No VPN)${N}"
    else
        PORT=$(echo "$DEFAULT_LINE" | grep -oP '127.0.0.1:\K\d+')
        NAME=$(get_lane_name_by_port "$PORT")
        STATE="${G}Routed via $NAME (Port $PORT)${N}"
    fi
    
    echo -e "Current: $STATE"
    echo "1. Restore to VPS Direct"
    echo "2. Route via Lane"
    echo "3. Back"
    read -p "Select: " OPT
    
    if [ "$OPT" == "1" ]; then
        sed -i 's/default.*;/default              \$ssl_preread_server_name:443;/g' $NGINX
        echo -e "${G}Restored to Direct.${N}"
    elif [ "$OPT" == "2" ]; then
        list_services
        echo ""
        TARGET=$(get_input "Enter Port: ")
        sed -i 's/default.*;/default              127.0.0.1:'"$TARGET"';/g' $NGINX
        echo -e "${G}Updated.${N}"
    fi
    systemctl restart nginx
}

list_services() {
    echo -e "${C}--- Active Lanes ---${N}"
    ls /etc/systemd/system/gost-*.service 2>/dev/null | while read f; do
        NAME=$(basename "$f" | sed 's/gost-//;s/.service//')
        PORT=$(grep -oP 'sni://:\K\d+' "$f")
        echo -e "Name: ${Y}$NAME${N} | Port: ${C}$PORT${N}"
    done
}

remove_lane() {
    echo -e "${R}>>> DELETE LANE <<<${N}"
    list_services
    echo ""
    TARGET=$(get_input "Enter name to delete: ")
    
    SERVICE="/etc/systemd/system/gost-$TARGET.service"
    [ ! -f "$SERVICE" ] && echo "Not found" && return

    PORT=$(grep -oP 'sni://:\K\d+' "$SERVICE")
    
    systemctl disable --now "gost-$TARGET" >/dev/null 2>&1
    rm "$SERVICE"
    systemctl daemon-reload

    find "$BASE_DIR" -maxdepth 1 -name "vpn-$TARGET" -type d 2>/dev/null | while read dir; do
        cd "$dir" && docker compose down >/dev/null 2>&1
        cd "$BASE_DIR" && rm -rf "$dir"
    done

    sed -i "/127.0.0.1:$PORT;/d" /etc/nginx/nginx.conf
    if grep -q "default              127.0.0.1:$PORT;" /etc/nginx/nginx.conf; then
        sed -i 's/default              127.0.0.1:'"$PORT"';/default              \$ssl_preread_server_name:443;/g' /etc/nginx/nginx.conf
    fi

    systemctl restart nginx
    echo -e "${G}Deleted.${N}"
}

add_domains() {
    list_services
    echo ""
    TARGET=$(get_input "Enter Lane Port: ")
    
    echo "Enter domain (e.g. ~.ip.me). Empty to stop."
    echo "READ ME!! e.g. ~.ip.me will ONLY cover subdomains." 
    echo "If you access it via www.ip.me, it will get routed. But if you access it via https://ip.me, it won't"
    echo "In that case, you would need to add both rules 'ip.me' and '~.ip.me' "
    while true; do
        read -p "Domain: " DOM
        [ -z "$DOM" ] && break
        sed -i "/default/i \ \ \ \ \ \ \ \ $DOM    127.0.0.1:$TARGET;" /etc/nginx/nginx.conf
        systemctl restart nginx
        echo "Added."
    done
}

remove_domains() {
    list_services
    echo ""
    TARGET=$(get_input "Enter Lane Port: ")
    
    echo -e "${C}Domains on this port:${N}"
    grep "127.0.0.1:$TARGET;" /etc/nginx/nginx.conf | awk '{print $1}'
    
    echo ""
    DOM=$(get_input "Enter exact domain to remove: ")
    sed -i "/$DOM.*127.0.0.1:$TARGET;/d" /etc/nginx/nginx.conf
    systemctl restart nginx
    echo "Removed."
}

update_creds() {
    echo -e "${C}>>> UPDATE ADGUARD CREDENTIALS <<<${N}"
    CONFIG="$BASE_DIR/dns-teleport/adguard/conf/AdGuardHome.yaml"
    [ ! -f "$CONFIG" ] && echo -e "${R}Config not found.${N}" && return

    NEW_USER=$(get_input "New Username: ")
    read -s -p "New Password: " NEW_PASS
    echo ""
    
    HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'$NEW_PASS', bcrypt.gensalt()).decode())")
    
    export P_USER="$NEW_USER"
    export P_HASH="$HASH"
    
    perl -i -pe 'BEGIN{undef $/;} s/(users:\n\s+-\s+name:).*/$1 $ENV{P_USER}/m' "$CONFIG"
    perl -i -pe 'BEGIN{undef $/;} s/(users:\n\s+-\s+name:.*?\n\s+password:).*/$1 $ENV{P_HASH}/s' "$CONFIG"
    
    echo "Restarting AdGuard..."
    cd "$BASE_DIR/dns-teleport" && docker compose restart
    echo -e "${G}Success! New credentials active.${N}"
}

edit_configs() {
    echo "1. Nginx"
    echo "2. Dnsmasq"
    echo "3. Edit Lane (GOST)"
    echo "4. AdGuard Config"
    echo "5. Back"
    read -p "Select: " OPT

    case $OPT in
        1) nano /etc/nginx/nginx.conf; systemctl restart nginx ;;
        2) nano /etc/dnsmasq.conf; systemctl restart dnsmasq ;;
        3) 
           list_services; read -p "Name: " L; 
           nano "/etc/systemd/system/gost-$L.service"; 
           systemctl daemon-reload; systemctl restart "gost-$L" 
           ;;
        4) 
           cd "$BASE_DIR/dns-teleport"
           nano "adguard/conf/AdGuardHome.yaml"
           docker compose restart
           ;;
    esac
}

uninstall_all() {
    echo -e "${R}WARNING: FULL UNINSTALL${N}"
    read -p "Type 'delete' to confirm: " CONFIRM
    if [ "$CONFIRM" != "delete" ]; then return; fi

    echo "Stopping..."
    systemctl stop nginx dnsmasq adguardhome 2>/dev/null
    
    ls /etc/systemd/system/gost-*.service 2>/dev/null | while read f; do
        NAME=$(basename "$f")
        systemctl disable --now "$NAME"
        rm "$f"
    done
    systemctl daemon-reload

    [ -d "$BASE_DIR/dns-teleport" ] && cd "$BASE_DIR/dns-teleport" && docker compose down
    find "$BASE_DIR" -maxdepth 1 -name "vpn-*" -type d 2>/dev/null | while read dir; do
        cd "$dir" && docker compose down
        rm -rf "$dir"
    done

    rm -rf "$BASE_DIR/dns-teleport"
    rm /etc/dnsmasq.conf /etc/nginx/nginx.conf "$CONFIG_FILE"
    mv /etc/dnsmasq.conf.bak /etc/dnsmasq.conf 2>/dev/null

    systemctl enable --now systemd-resolved
    rm /etc/resolv.conf
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    
    ufw disable
    echo -e "${G}Done.${N}"
    exit 0
}

while true; do
    echo ""
    echo -e "${G}=== s0n1c's DNS teleport manager (private setup) ===${N}"
    echo "1. Setup System"
    echo "2. Add VPN Lane"
    echo "3. Add Proxy Lane"
    echo "4. Traffic Routing"
    echo "5. List Lanes"
    echo "6. Delete Lane"
    echo "7. Add Domain (SmartDNS)"
    echo "8. Remove Domain"
    echo "9. Edit Configs"
    echo "10. Update Credentials"
    echo "11. Uninstall"
    echo "12. Exit"
    echo -e "${Y}----------------------------${N}"
    read -p "Select: " OPTION

    case $OPTION in
        1) setup_base ;;
        2) setup_vpn ;;
        3) setup_proxy ;;
        4) manage_routing ;;
        5) list_services ;;
        6) remove_lane ;;
        7) add_domains ;;
        8) remove_domains ;;
        9) edit_configs ;;
        10) update_creds ;;
        11) uninstall_all ;;
        12) exit 0 ;;
        *) echo "Invalid" ;;
    esac
done
