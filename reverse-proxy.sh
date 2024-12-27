#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Updated paths for macOS Homebrew
NGINX_BASE="/opt/homebrew/etc/nginx"
NGINX_SITES_DIR="$NGINX_BASE/sites-enabled"
CERT_DIR="$HOME/.local/share/proxy-pal/certs"
LAST_DOMAIN_FILE="$HOME/.local/share/proxy-pal/.last_domain"

# Function to ensure directories exist with proper permissions
ensure_directories() {
    local dirs=(
        "$NGINX_BASE"
        "$NGINX_SITES_DIR"
        "/opt/homebrew/var/log/nginx"
        "/opt/homebrew/var/run/nginx"
        "$CERT_DIR"
    )

    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            echo "Creating directory: $dir"
            sudo mkdir -p "$dir"
            sudo chown $(whoami):admin "$dir"
            sudo chmod 755 "$dir"
        fi
    done
}

# Function to create required directories
create_directories() {
    echo -e "${YELLOW}Creating required directories...${NC}"
    
    # Create Nginx directories
    sudo mkdir -p "$NGINX_SITES_DIR"
    sudo mkdir -p "/opt/homebrew/var/log/nginx"
    sudo mkdir -p "/opt/homebrew/var/run/nginx"
    
    # Create certificate directory
    mkdir -p "$CERT_DIR"
    
    # Set proper permissions
    sudo chown -R $(whoami):admin "$NGINX_BASE"
    sudo chown -R $(whoami):admin "/opt/homebrew/var/log/nginx"
    sudo chown -R $(whoami):admin "/opt/homebrew/var/run/nginx"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if string exists in file
string_exists_in_file() {
    local string=$1
    local file=$2
    grep -q "$string" "$file" 2>/dev/null
    return $?
}

# Function to install required tools
install_requirements() {
    if ! command_exists brew; then
        echo -e "${RED}Homebrew is required. Please install it first.${NC}"
        exit 1
    fi

    if ! command_exists nginx; then
        echo -e "${YELLOW}Installing nginx...${NC}"
        brew install nginx
    fi

    if ! command_exists mkcert; then
        echo -e "${YELLOW}Installing mkcert...${NC}"
        brew install mkcert
        brew install nss # for Firefox support
    fi
}

# Function to update Nginx main configuration
update_nginx_main_config() {
    echo -e "${YELLOW}Updating Nginx main configuration...${NC}"
    
    # Backup existing config if it exists
    if [ -f "$NGINX_BASE/nginx.conf" ]; then
        sudo cp "$NGINX_BASE/nginx.conf" "$NGINX_BASE/nginx.conf.backup"
    fi
    
    # Create new main configuration
    sudo tee "$NGINX_BASE/nginx.conf" > /dev/null << 'EOF'
worker_processes auto;
pid /opt/homebrew/var/run/nginx/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    access_log /opt/homebrew/var/log/nginx/access.log;
    error_log /opt/homebrew/var/log/nginx/error.log debug;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Include all site configurations
    include /opt/homebrew/etc/nginx/sites-enabled/*.conf;
}
EOF
}

# Function to update /etc/hosts
update_hosts() {
    local domain=$1
    local base_domain=$(echo $domain | sed 's/^www\.//')
    local hosts_entry="127.0.0.1 ${domain} ${base_domain}"
    
    echo -e "${YELLOW}Updating /etc/hosts...${NC}"
    
    if ! string_exists_in_file "${domain}" "/etc/hosts"; then
        echo "Adding hosts entry..."
        echo "$hosts_entry" | sudo tee -a /etc/hosts > /dev/null
        echo -e "${GREEN}Hosts file updated successfully${NC}"
    else
        echo -e "${YELLOW}Domain already exists in /etc/hosts${NC}"
    fi

    # Save domain for later use
    echo "$domain" > "$LAST_DOMAIN_FILE"
}

# Function to generate SSL certificates
generate_ssl() {
    local domain=$1
    local base_domain=$(echo $domain | sed 's/^www\.//')
    
    echo -e "${YELLOW}Generating SSL certificates...${NC}"
    
    # Create certificates directory if it doesn't exist
    mkdir -p "$CERT_DIR"
    
    # Initialize mkcert if not already done
    if [ ! -f "$HOME/.local/share/mkcert/rootCA.pem" ]; then
        echo "Initializing mkcert..."
        mkcert -install
    fi
    
    # Generate certificate for both www and non-www versions
    echo "Generating certificates for ${domain} and ${base_domain}..."
    mkcert -key-file "$CERT_DIR/${base_domain}-key.pem" \
           -cert-file "$CERT_DIR/${base_domain}-cert.pem" \
           "${domain}" "${base_domain}" "localhost" "127.0.0.1" "::1"
    
    echo -e "${GREEN}SSL certificates generated successfully${NC}"
}

# Function to create site configuration
create_nginx_config() {
    local target_url=$1
    local domain=$(cat "$LAST_DOMAIN_FILE")
    local base_domain=$(echo $domain | sed 's/^www\.//')
    
    echo -e "${YELLOW}Creating site configuration...${NC}"

      # Ensure the sites-enabled directory exists
    ensure_directories
    
    # Create the configuration file
    sudo tee "$NGINX_SITES_DIR/${base_domain}.conf" > /dev/null << EOF
# HTTPS Server
server {
    listen 443 ssl;
    http2;
    listen [::]:443 ssl;
    http2;
    server_name ${domain} ${base_domain};

    ssl_certificate $CERT_DIR/${base_domain}-cert.pem;
    ssl_certificate_key $CERT_DIR/${base_domain}-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass ${target_url};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# HTTP redirect
server {
    listen 80;
    listen [::]:80;
    server_name ${domain} ${base_domain};
    return 301 https://\$host\$request_uri;
}
EOF

    # Verify the file was created
    if [ ! -f "$NGINX_SITES_DIR/${base_domain}.conf" ]; then
        echo -e "${RED}Failed to create Nginx configuration file${NC}"
        exit 1
    fi
}

# Function to restart Nginx
restart_nginx() {
    echo -e "${YELLOW}Restarting Nginx...${NC}"
    
    # Test configuration
    if ! sudo nginx -t; then
        echo -e "${RED}Nginx configuration test failed${NC}"
        exit 1
    fi
    
    # Restart service
    sudo brew services reload nginx
    
    echo -e "${GREEN}Nginx restarted successfully${NC}"
}

# Setup command
setup() {
    local domain=$1
    
    # Validate domain format
    if [[ ! $domain =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Invalid domain format. Please use a valid domain name.${NC}"
        exit 1
    fi
    
    # Install required tools
    install_requirements

    # Ensure directories exist
    ensure_directories

    # Create required directories
    create_directories
    
    # Update main Nginx configuration
    update_nginx_main_config
    
    # Update hosts file
    update_hosts "$domain"
    
    # Generate SSL certificates
    generate_ssl "$domain"
    
    echo -e "\n${GREEN}Setup completed successfully!${NC}"
    echo -e "${YELLOW}Use 'pp link <target-url>' to create the reverse proxy${NC}"
}

# Link command
link() {
    local target_url=$1

    # Check if setup was run first
    if [ ! -f "$LAST_DOMAIN_FILE" ]; then
        echo -e "${RED}Error: Please run 'pp setup <domain>' first${NC}"
        exit 1
    fi

    # Validate target URL
    if [[ ! $target_url =~ ^http[s]?:// ]]; then
        echo -e "${RED}Invalid target URL. Please include http:// or https://${NC}"
        exit 1
    fi

    # Create Nginx configuration
    create_nginx_config "$target_url"

    # Restart Nginx
    restart_nginx

    local domain=$(cat "$LAST_DOMAIN_FILE")
    echo -e "\n${GREEN}Reverse proxy setup completed!${NC}"
    echo -e "${YELLOW}Your site is now available at:${NC}"
    echo -e "  https://${domain}"
}

unlink() {
    local domain=$1
    
    if ! string_exists_in_file "$domain" "$LAST_DOMAIN_FILE"; then
        echo -e "${RED}Error: Domain does not exist${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Unlinking ${domain}...${NC}"
    
    local base_domain=$(echo $domain | sed 's/^www\.//')

    # Remove Nginx configuration files
    sudo rm -f "$NGINX_SITES_DIR/${base_domain}.conf"
    
    # Restart Nginx
    restart_nginx
    
    echo -e "${GREEN}Unlink completed successfully${NC}"
}

# write me a cleanup function to remove the created files and directories
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    # Remove Nginx configuration files
    local domain=$(cat "$LAST_DOMAIN_FILE")
    local base_domain=$(echo $domain | sed 's/^www\.//')

    sudo rm -f "$NGINX_SITES_DIR/${base_domain}.conf"
    
    # Remove certificates
    rm -rf "$CERT_DIR"
    
    # Remove last domain file
    rm -f "$LAST_DOMAIN_FILE"
    
    echo -e "${GREEN}Cleanup completed successfully${NC}"
}

# Show help
show_help() {
    echo "Usage: pp <command> <argument>"
    echo ""
    echo "Commands:"
    echo "  setup <domain>     Setup local domain with SSL certificates"
    echo "  link <target-url>  Create reverse proxy to target URL"
    echo "  unlink <domain>    Remove reverse proxy for domain"
    echo "  cleanup            Remove all created files and directories"
    echo "  help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  pp setup www.nixify.dev"
    echo "  pp link http://localhost:3000/"
    echo ""
}

# Create necessary directories
mkdir -p "$HOME/.local/share/proxy-pal"

# Main script logic
case $1 in
    setup)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Domain name is required${NC}"
            show_help
            exit 1
        fi
        setup "$2"
        ;;
    link)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Target URL is required${NC}"
            show_help
            exit 1
        fi
        link "$2"
        ;;
    unlink)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Domain name is required${NC}"
            show_help
            exit 1
        fi
        unlink "$2"
        ;;
    help)
        show_help
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        show_help
        exit 1
        ;;
esac