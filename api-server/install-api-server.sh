#!/bin/bash

# Resume Robot API Server Setup Script
# Version: 3.0.0
# Purpose: Complete automated setup of Resume Robot API server on Ubuntu 22.04 LTS with remote PostgreSQL database
# Requirements: Fresh Ubuntu 22.04 LTS server (2GB RAM, 2 vCPU, 60GB SSD minimum) + Remote PostgreSQL server

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# =============================================================================
# CONFIGURATION VARIABLES
# =============================================================================

SCRIPT_VERSION="3.0.0"
LOG_FILE="/var/log/resume-robot-setup.log"
SETUP_DIR="/opt/resume-robot"
APP_USER="resumerobot"
APP_DIR="/home/$APP_USER/api"
DOMAIN=""  # Will be prompted
DB_HOST=""  # Will be prompted
DB_PORT="5432"  # Will be prompted
DB_SUPERUSER=""  # Will be prompted
DB_SUPERUSER_PASSWORD=""  # Will be prompted
DB_NAME="resumerobot_db"
DB_USER="resumerobot_user"
DB_PASSWORD=""  # Will be generated
NODE_VERSION="18"
NGINX_CONFIG_DIR="/etc/nginx/sites-available"
SSL_DIR="/etc/ssl/resume-robot"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# LOGGING AND UTILITY FUNCTIONS
# =============================================================================

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

check_ubuntu_version() {
    if ! grep -q "Ubuntu 22.04" /etc/os-release; then
        warn "This script is designed for Ubuntu 22.04 LTS. Proceeding anyway..."
    fi
}

generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

prompt_for_input() {
    local prompt="$1"
    local var_name="$2"
    local default_value="${3:-}"
    local hide_input="${4:-false}"
    
    while true; do
        if [[ "$hide_input" == "true" ]]; then
            read -s -p "$prompt: " input
            echo
        else
            if [[ -n "$default_value" ]]; then
                read -p "$prompt [$default_value]: " input
                input="${input:-$default_value}"
            else
                read -p "$prompt: " input
            fi
        fi
        
        if [[ -n "$input" ]]; then
            declare -g "$var_name=$input"
            break
        else
            error "Input cannot be empty. Please try again."
        fi
    done
}

# =============================================================================
# SYSTEM PREPARATION
# =============================================================================

update_system() {
    log "Updating system packages..."
    apt update -y
    apt upgrade -y
    apt install -y curl wget git unzip software-properties-common apt-transport-https ca-certificates gnupg lsb-release
}

install_nodejs() {
    log "Installing Node.js $NODE_VERSION..."
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
    apt install -y nodejs
    
    # Verify installation
    node_version=$(node --version)
    npm_version=$(npm --version)
    log "Node.js installed: $node_version, npm: $npm_version"
}

install_postgresql_client() {
    log "Installing PostgreSQL client tools..."
    apt install -y postgresql-client-14
    
    # Verify installation
    psql_version=$(psql --version)
    log "PostgreSQL client installed: $psql_version"
}

install_nginx() {
    log "Installing Nginx..."
    apt install -y nginx
    
    # Start and enable Nginx
    systemctl start nginx
    systemctl enable nginx
    
    # Verify installation
    nginx_version=$(nginx -v 2>&1)
    log "Nginx installed: $nginx_version"
}

install_pm2() {
    log "Installing PM2 process manager..."
    npm install -g pm2
    
    # Setup PM2 startup script
    env PATH=$PATH:/usr/bin pm2 startup systemd -u $APP_USER --hp /home/$APP_USER
    
    pm2_version=$(pm2 --version)
    log "PM2 installed: $pm2_version"
}

install_certbot() {
    log "Installing Certbot for SSL certificates..."
    apt install -y certbot python3-certbot-nginx
    
    certbot_version=$(certbot --version)
    log "Certbot installed: $certbot_version"
}

# =============================================================================
# USER AND DIRECTORY SETUP
# =============================================================================

create_app_user() {
    log "Creating application user: $APP_USER"
    
    if id "$APP_USER" &>/dev/null; then
        warn "User $APP_USER already exists"
    else
        useradd -m -s /bin/bash "$APP_USER"
        log "User $APP_USER created successfully"
    fi
    
    # Create application directory
    mkdir -p "$APP_DIR"
    chown -R "$APP_USER:$APP_USER" "/home/$APP_USER"
}

setup_directories() {
    log "Setting up directory structure..."
    
    mkdir -p "$SETUP_DIR"
    mkdir -p "$SSL_DIR"
    mkdir -p "/var/log/resume-robot"
    mkdir -p "/var/lib/resume-robot/uploads"
    mkdir -p "/var/lib/resume-robot/backups"
    
    # Set permissions
    chown -R "$APP_USER:$APP_USER" "/var/log/resume-robot"
    chown -R "$APP_USER:$APP_USER" "/var/lib/resume-robot"
    chmod 755 "/var/lib/resume-robot"
    chmod 700 "/var/lib/resume-robot/uploads"
    chmod 700 "/var/lib/resume-robot/backups"
}

# =============================================================================
# DATABASE SETUP
# =============================================================================

setup_database() {
    log "Setting up remote PostgreSQL database..."
    
    # Generate database password if not set
    if [[ -z "$DB_PASSWORD" ]]; then
        DB_PASSWORD=$(generate_password)
    fi
    
    # Test connection to remote database server
    log "Testing connection to remote database server..."
    if ! PGPASSWORD="$DB_SUPERUSER_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_SUPERUSER" -d postgres -c "SELECT 1;" >/dev/null 2>&1; then
        error "Cannot connect to remote database server at $DB_HOST:$DB_PORT with provided credentials"
    fi
    
    log "Connection to remote database server successful"
    
    # Create database and user on remote server
    log "Creating database and user on remote server..."
    PGPASSWORD="$DB_SUPERUSER_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_SUPERUSER" -d postgres << EOF
-- Create database if it doesn't exist
SELECT 'CREATE DATABASE $DB_NAME' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DB_NAME')\gexec

-- Create user if it doesn't exist
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$DB_USER') THEN
      CREATE USER $DB_USER WITH ENCRYPTED PASSWORD '$DB_PASSWORD';
   ELSE
      ALTER USER $DB_USER WITH ENCRYPTED PASSWORD '$DB_PASSWORD';
   END IF;
END
\$\$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
ALTER USER $DB_USER CREATEDB;

-- Connect to the new database and grant schema privileges
\c $DB_NAME;
GRANT ALL PRIVILEGES ON SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO $DB_USER;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON FUNCTIONS TO $DB_USER;

\q
EOF
    
    # Test connection with new user
    if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" >/dev/null 2>&1; then
        log "Database user connection test successful"
    else
        error "Database user connection test failed"
    fi
    
    # Save database credentials securely
    cat > "$SETUP_DIR/db_credentials.txt" << EOF
Database Host: $DB_HOST
Database Port: $DB_PORT
Database Name: $DB_NAME
Database User: $DB_USER
Database Password: $DB_PASSWORD
Database Superuser: $DB_SUPERUSER
Connection String: postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME
EOF
    
    chmod 600 "$SETUP_DIR/db_credentials.txt"
    chown root:root "$SETUP_DIR/db_credentials.txt"
    
    log "Database credentials saved to $SETUP_DIR/db_credentials.txt"
}

# =============================================================================
# APPLICATION SETUP
# =============================================================================

clone_api_repository() {
    log "Cloning Resume Robot API repository..."
    
    # Prompt for GitHub repository URL
    prompt_for_input "Enter the GitHub repository URL for the API" "REPO_URL"
    
    # Clone repository as app user
    sudo -u "$APP_USER" bash << EOF
cd /home/$APP_USER
if [[ -d "api" ]]; then
    rm -rf api
fi
git clone "$REPO_URL" api
cd api
git checkout main 2>/dev/null || git checkout master 2>/dev/null || true
EOF
    
    log "Repository cloned successfully"
}

install_dependencies() {
    log "Installing Node.js dependencies..."
    
    sudo -u "$APP_USER" bash << EOF
cd "$APP_DIR"
npm install --production
EOF
    
    log "Dependencies installed successfully"
}

create_env_file() {
    log "Creating environment configuration..."
    
    # Generate JWT secret
    JWT_SECRET=$(generate_password)
    
    # Generate encryption key
    ENCRYPTION_KEY=$(openssl rand -hex 32)
    
    # Create .env file
    sudo -u "$APP_USER" cat > "$APP_DIR/.env" << EOF
# Resume Robot API Configuration
NODE_ENV=production
PORT=3000

# Database Configuration
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD

# Security
JWT_SECRET=$JWT_SECRET
JWT_EXPIRES_IN=24h
ENCRYPTION_KEY=$ENCRYPTION_KEY

# CORS Configuration
CORS_ORIGIN=https://$DOMAIN

# File Upload Configuration
UPLOAD_DIR=/var/lib/resume-robot/uploads
MAX_FILE_SIZE=5242880

# OpenAI Configuration (to be configured later)
OPENAI_API_KEY=your_openai_api_key_here

# Email Configuration (to be configured later)
EMAIL_SERVICE=smtp
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password

# Admin Configuration
ADMIN_EMAIL=admin@$DOMAIN
ADMIN_PASSWORD=$(generate_password)

# Logging
LOG_LEVEL=info
LOG_FILE=/var/log/resume-robot/api.log

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Session Configuration
SESSION_SECRET=$(generate_password)

# Backup Configuration
BACKUP_DIR=/var/lib/resume-robot/backups
BACKUP_RETENTION_DAYS=30
EOF
    
    chmod 600 "$APP_DIR/.env"
    chown "$APP_USER:$APP_USER" "$APP_DIR/.env"
    
    log "Environment file created with secure credentials"
}

run_database_migrations() {
    log "Running database migrations..."
    
    sudo -u "$APP_USER" bash << EOF
cd "$APP_DIR"
if [[ -f "scripts/migrate.js" ]]; then
    node scripts/migrate.js
elif [[ -f "database/migrate.js" ]]; then
    node database/migrate.js
else
    echo "No migration script found, skipping..."
fi
EOF
    
    log "Database migrations completed"
}

# =============================================================================
# NGINX CONFIGURATION
# =============================================================================

configure_nginx() {
    log "Configuring Nginx..."
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    # Create Resume Robot API site configuration
    cat > "$NGINX_CONFIG_DIR/resume-robot-api" << 'EOF'
server {
    listen 80;
    server_name DOMAIN_PLACEHOLDER;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    # File upload size limit
    client_max_body_size 10M;
    
    # API proxy
    location /api/ {
        proxy_pass http://localhost:3000/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://localhost:3000/health;
        access_log off;
    }
    
    # Block access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ \.(env|log|sql)$ {
        deny all;
    }
}
EOF
    
    # Replace domain placeholder
    sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" "$NGINX_CONFIG_DIR/resume-robot-api"
    
    # Enable site
    ln -sf "$NGINX_CONFIG_DIR/resume-robot-api" /etc/nginx/sites-enabled/
    
    # Test Nginx configuration
    if nginx -t; then
        systemctl reload nginx
        log "Nginx configuration applied successfully"
    else
        error "Nginx configuration test failed"
    fi
}

# =============================================================================
# SSL CERTIFICATE SETUP
# =============================================================================

setup_ssl() {
    log "Setting up SSL certificate with Let's Encrypt..."
    
    # Obtain SSL certificate
    if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" --redirect; then
        log "SSL certificate obtained and configured successfully"
    else
        warn "SSL certificate setup failed. You may need to configure it manually later."
    fi
    
    # Setup automatic renewal
    systemctl enable certbot.timer
    systemctl start certbot.timer
    
    log "SSL certificate auto-renewal configured"
}

# =============================================================================
# PM2 CONFIGURATION
# =============================================================================

configure_pm2() {
    log "Configuring PM2 process manager..."
    
    # Create PM2 ecosystem file
    sudo -u "$APP_USER" cat > "$APP_DIR/ecosystem.config.js" << EOF
module.exports = {
  apps: [{
    name: 'resume-robot-api',
    script: 'server.js',
    cwd: '$APP_DIR',
    instances: 'max',
    exec_mode: 'cluster',
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    error_file: '/var/log/resume-robot/api-error.log',
    out_file: '/var/log/resume-robot/api-out.log',
    log_file: '/var/log/resume-robot/api-combined.log',
    time: true,
    max_restarts: 10,
    min_uptime: '10s',
    restart_delay: 4000
  }]
};
EOF
    
    # Start application with PM2
    sudo -u "$APP_USER" bash << EOF
cd "$APP_DIR"
pm2 start ecosystem.config.js
pm2 save
EOF
    
    # Generate startup script
    pm2 startup systemd -u "$APP_USER" --hp "/home/$APP_USER"
    
    log "PM2 configured and application started"
}

# =============================================================================
# FIREWALL CONFIGURATION
# =============================================================================

configure_firewall() {
    log "Configuring UFW firewall..."
    
    # Reset firewall rules
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (be careful not to lock yourself out)
    ufw allow ssh
    
    # Allow HTTP and HTTPS
    ufw allow 'Nginx Full'
    
    # Note: PostgreSQL is on remote server, no local firewall rules needed
    
    # Enable firewall
    ufw --force enable
    
    log "Firewall configured successfully"
}

# =============================================================================
# MONITORING AND LOGGING SETUP
# =============================================================================

setup_monitoring() {
    log "Setting up monitoring and logging..."
    
    # Create log rotation configuration
    cat > /etc/logrotate.d/resume-robot << EOF
/var/log/resume-robot/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 644 $APP_USER $APP_USER
    postrotate
        sudo -u $APP_USER pm2 reloadLogs
    endscript
}
EOF
    
    # Create health check script
    cat > "$SETUP_DIR/healthcheck.sh" << EOF
#!/bin/bash
# Resume Robot API Health Check

API_URL="http://localhost:3000/health"
LOG_FILE="/var/log/resume-robot/healthcheck.log"

response=\$(curl -s -o /dev/null -w "%{http_code}" "\$API_URL" 2>/dev/null)

if [[ "\$response" == "200" ]]; then
    echo "[\$(date)] API Health Check: OK" >> "\$LOG_FILE"
    exit 0
else
    echo "[\$(date)] API Health Check: FAILED (HTTP \$response)" >> "\$LOG_FILE"
    # Restart API if health check fails
    sudo -u $APP_USER pm2 restart resume-robot-api
    exit 1
fi
EOF
    
    chmod +x "$SETUP_DIR/healthcheck.sh"
    
    # Setup cron job for health monitoring
    cat > /etc/cron.d/resume-robot-healthcheck << EOF
# Resume Robot API Health Check - every 5 minutes
*/5 * * * * root $SETUP_DIR/healthcheck.sh
EOF
    
    log "Monitoring and logging configured"
}

# =============================================================================
# BACKUP CONFIGURATION
# =============================================================================

setup_backups() {
    log "Setting up automated backups..."
    
    # Create backup script
    cat > "$SETUP_DIR/backup.sh" << EOF
#!/bin/bash
# Resume Robot Automated Backup Script

BACKUP_DIR="/var/lib/resume-robot/backups"
DB_HOST="$DB_HOST"
DB_PORT="$DB_PORT"
DB_NAME="$DB_NAME"
DB_USER="$DB_USER"
DB_PASSWORD="$DB_PASSWORD"
APP_DIR="$APP_DIR"
RETENTION_DAYS=30

# Create timestamp
TIMESTAMP=\$(date +%Y%m%d_%H%M%S)

# Database backup
echo "Creating database backup..."
PGPASSWORD="\$DB_PASSWORD" pg_dump -h "\$DB_HOST" -p "\$DB_PORT" -U "\$DB_USER" "\$DB_NAME" > "\$BACKUP_DIR/db_backup_\$TIMESTAMP.sql"

# Application files backup
echo "Creating application backup..."
tar -czf "\$BACKUP_DIR/app_backup_\$TIMESTAMP.tar.gz" -C "\$(dirname \$APP_DIR)" "\$(basename \$APP_DIR)" --exclude="node_modules" --exclude=".git"

# Cleanup old backups
find "\$BACKUP_DIR" -name "*.sql" -mtime +\$RETENTION_DAYS -delete
find "\$BACKUP_DIR" -name "*.tar.gz" -mtime +\$RETENTION_DAYS -delete

echo "Backup completed: \$TIMESTAMP"
EOF
    
    chmod +x "$SETUP_DIR/backup.sh"
    
    # Setup daily backup cron job
    cat > /etc/cron.d/resume-robot-backup << EOF
# Resume Robot Daily Backup - 2 AM daily
0 2 * * * root $SETUP_DIR/backup.sh >> /var/log/resume-robot/backup.log 2>&1
EOF
    
    # Run initial backup
    "$SETUP_DIR/backup.sh"
    
    log "Backup system configured and initial backup completed"
}

# =============================================================================
# SECURITY HARDENING
# =============================================================================

security_hardening() {
    log "Applying security hardening..."
    
    # Disable root login
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    
    # Disable password authentication (assumes SSH keys are configured)
    # sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # Install fail2ban
    apt install -y fail2ban
    
    # Configure fail2ban for SSH and Nginx
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
EOF
    
    systemctl enable fail2ban
    systemctl start fail2ban
    
    # Set up automatic security updates
    apt install -y unattended-upgrades
    echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    
    systemctl restart ssh
    
    log "Security hardening completed"
}

# =============================================================================
# POST-INSTALLATION TASKS
# =============================================================================

create_admin_scripts() {
    log "Creating administration scripts..."
    
    # API status script
    cat > "$SETUP_DIR/status.sh" << EOF
#!/bin/bash
echo "=== Resume Robot API Status ==="
echo "Application Status:"
sudo -u $APP_USER pm2 status resume-robot-api
echo ""
echo "Database Connection:"
if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 'Database: Connected' as status;" 2>/dev/null; then
    echo "✅ Database connection successful"
else
    echo "❌ Database connection failed"
fi
echo ""
echo "Nginx Status:"
systemctl status nginx --no-pager -l
echo ""
echo "Disk Usage:"
df -h /var/lib/resume-robot
echo ""
echo "Recent Logs:"
tail -n 10 /var/log/resume-robot/api-combined.log
EOF
    
    # API restart script
    cat > "$SETUP_DIR/restart.sh" << EOF
#!/bin/bash
echo "Restarting Resume Robot API..."
sudo -u $APP_USER pm2 restart resume-robot-api
systemctl reload nginx
echo "Restart completed"
EOF
    
    # Update script
    cat > "$SETUP_DIR/update.sh" << EOF
#!/bin/bash
echo "Updating Resume Robot API..."
sudo -u $APP_USER bash << 'USEREOF'
cd $APP_DIR
git pull origin main
npm install --production
USEREOF
sudo -u $APP_USER pm2 restart resume-robot-api
echo "Update completed"
EOF
    
    chmod +x "$SETUP_DIR"/*.sh
    
    log "Administration scripts created in $SETUP_DIR"
}

generate_summary_report() {
    log "Generating installation summary report..."
    
    cat > "$SETUP_DIR/installation_summary.txt" << EOF
=== Resume Robot API Server Installation Summary ===
Installation Date: $(date)
Script Version: $SCRIPT_VERSION
Server: $(hostname)
Domain: $DOMAIN

=== Installed Components ===
- Ubuntu $(lsb_release -rs)
- Node.js $(node --version)
- PostgreSQL Client $(psql --version | cut -d' ' -f3)
- Nginx $(nginx -v 2>&1 | cut -d' ' -f3)
- PM2 $(pm2 --version)
- Certbot $(certbot --version | cut -d' ' -f2)

=== Remote Database ===
Database Server: $DB_HOST:$DB_PORT
Database Name: $DB_NAME
Database User: $DB_USER
Connection Status: $(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 'Connected'" 2>/dev/null | grep Connected || echo "Connection Test Failed")

=== Database Information ===
Database Host: $DB_HOST
Database Port: $DB_PORT
Database Name: $DB_NAME
Database User: $DB_USER
Connection: postgresql://$DB_USER:***@$DB_HOST:$DB_PORT/$DB_NAME

=== Application Information ===
Application User: $APP_USER
Application Directory: $APP_DIR
Log Directory: /var/log/resume-robot
Upload Directory: /var/lib/resume-robot/uploads
Backup Directory: /var/lib/resume-robot/backups

=== URLs ===
API URL: https://$DOMAIN/api/
Health Check: https://$DOMAIN/health

=== Important Files ===
Environment Config: $APP_DIR/.env
Nginx Config: $NGINX_CONFIG_DIR/resume-robot-api
PM2 Config: $APP_DIR/ecosystem.config.js
Database Credentials: $SETUP_DIR/db_credentials.txt

=== Administration Scripts ===
Status Check: $SETUP_DIR/status.sh
Restart API: $SETUP_DIR/restart.sh
Update API: $SETUP_DIR/update.sh
Health Check: $SETUP_DIR/healthcheck.sh
Backup: $SETUP_DIR/backup.sh

=== Next Steps ===
1. Configure OpenAI API key in $APP_DIR/.env
2. Configure email settings in $APP_DIR/.env
3. Test all API endpoints
4. Set up monitoring alerts
5. Configure regular backups to external storage

=== Security Notes ===
- Database password is stored in $SETUP_DIR/db_credentials.txt (root only)
- JWT secrets and encryption keys generated automatically
- SSL certificate configured with auto-renewal
- Firewall configured with minimal required ports
- Fail2ban configured for intrusion prevention

=== Support ===
- Log files: /var/log/resume-robot/
- Check status: $SETUP_DIR/status.sh
- Restart services: $SETUP_DIR/restart.sh
EOF
    
    log "Installation summary saved to $SETUP_DIR/installation_summary.txt"
}

# =============================================================================
# MAIN INSTALLATION FUNCTION
# =============================================================================

main() {
    log "Starting Resume Robot API Server Setup v$SCRIPT_VERSION"
    
    # Pre-installation checks
    check_root
    check_ubuntu_version
    
    # Create log file
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    # Gather required information
    info "Please provide the following information:"
    prompt_for_input "Enter your domain name (e.g., api.resumerobot.com)" "DOMAIN"
    
    echo -e "\n${BLUE}Database Server Configuration:${NC}"
    prompt_for_input "Enter database server IP address" "DB_HOST"
    prompt_for_input "Enter database server port" "DB_PORT" "5432"
    prompt_for_input "Enter database superuser username" "DB_SUPERUSER" "postgres"
    prompt_for_input "Enter database superuser password" "DB_SUPERUSER_PASSWORD" "" "true"
    
    # Confirm installation
    echo -e "\n${YELLOW}Installation Summary:${NC}"
    echo "Domain: $DOMAIN"
    echo "Database Host: $DB_HOST:$DB_PORT"
    echo "Database Superuser: $DB_SUPERUSER"
    echo "New Database: $DB_NAME"
    echo "New Database User: $DB_USER"
    echo "App User: $APP_USER"
    echo "Installation Directory: $APP_DIR"
    echo ""
    
    read -p "Proceed with installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Installation cancelled by user"
        exit 0
    fi
    
    # Main installation steps
    info "Starting installation process..."
    
    update_system
    install_nodejs
    install_postgresql_client
    install_nginx
    install_pm2
    install_certbot
    
    create_app_user
    setup_directories
    setup_database
    
    clone_api_repository
    install_dependencies
    create_env_file
    run_database_migrations
    
    configure_nginx
    setup_ssl
    configure_pm2
    
    configure_firewall
    setup_monitoring
    setup_backups
    security_hardening
    
    create_admin_scripts
    generate_summary_report
    
    # Final status check
    if sudo -u "$APP_USER" pm2 list | grep -q "resume-robot-api.*online"; then
        log "✅ Resume Robot API Server installation completed successfully!"
        log "🌐 Your API is now running at: https://$DOMAIN/api/"
        log "📊 Health check: https://$DOMAIN/health"
        log "🗄️ Remote database: $DB_HOST:$DB_PORT"
        log "📋 Installation summary: $SETUP_DIR/installation_summary.txt"
        log "🔧 Admin scripts available in: $SETUP_DIR/"
        
        echo -e "\n${GREEN}Next Steps:${NC}"
        echo "1. Configure OpenAI API key in $APP_DIR/.env"
        echo "2. Configure email settings in $APP_DIR/.env"
        echo "3. Test API endpoints"
        echo "4. Verify remote database connectivity"
        echo "5. Set up external backup storage"
        echo ""
        echo -e "${BLUE}Quick Commands:${NC}"
        echo "Check status: $SETUP_DIR/status.sh"
        echo "Restart API: $SETUP_DIR/restart.sh"
        echo "View logs: tail -f /var/log/resume-robot/api-combined.log"
    else
        error "Installation completed but API failed to start. Check logs for details."
    fi
}

# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi