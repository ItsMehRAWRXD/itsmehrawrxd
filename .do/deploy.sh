#!/bin/bash

#####################################
# Digital Ocean App Platform Deployment Script
# For existing app: orca
#####################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# App configuration
APP_ID="f7e8c6ff-12ff-4c2a-a62b-e8b537f2c8ca"
APP_NAME="orca"
GITHUB_REPO="ItsMehRAWRXD/itsmehrawrxd"
BRANCH="${BRANCH:-main}"

# Function to print colored output
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Check if doctl is installed
check_doctl() {
    if ! command -v doctl &> /dev/null; then
        print_message "$RED" "❌ doctl is not installed."
        print_message "$YELLOW" "Installing doctl..."
        
        # Detect OS and install accordingly
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            # Linux
            cd ~
            wget https://github.com/digitalocean/doctl/releases/download/v1.104.0/doctl-1.104.0-linux-amd64.tar.gz
            tar xf ~/doctl-1.104.0-linux-amd64.tar.gz
            sudo mv ~/doctl /usr/local/bin
            rm ~/doctl-1.104.0-linux-amd64.tar.gz
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            brew install doctl
        else
            print_message "$RED" "Please install doctl manually from:"
            print_message "$RED" "https://docs.digitalocean.com/reference/doctl/how-to/install/"
            exit 1
        fi
    fi
    
    print_message "$GREEN" "✅ doctl is installed"
}

# Authenticate with Digital Ocean
authenticate() {
    print_message "$BLUE" "🔐 Authenticating with Digital Ocean..."
    
    if ! doctl auth list | grep -q "current"; then
        print_message "$YELLOW" "Please authenticate with your Digital Ocean token:"
        doctl auth init
    else
        print_message "$GREEN" "✅ Already authenticated"
    fi
}

# Get app status
get_app_status() {
    print_message "$BLUE" "📊 Getting app status..."
    
    doctl apps get $APP_ID --format "ID,DefaultIngress,ActiveDeployment.Phase,UpdatedAt,LiveURL" --no-header
    
    # Get recent deployments
    print_message "$BLUE" "📋 Recent deployments:"
    doctl apps list-deployments $APP_ID --format "ID,Phase,CreatedAt,Cause.Type" --no-header | head -5
}

# Update app spec
update_app_spec() {
    print_message "$BLUE" "📝 Updating app specification..."
    
    # Validate the spec file
    if doctl apps spec validate .do/app.yaml; then
        print_message "$GREEN" "✅ App spec is valid"
        
        # Update the app
        doctl apps update $APP_ID --spec .do/app.yaml
        print_message "$GREEN" "✅ App spec updated successfully"
    else
        print_message "$RED" "❌ App spec validation failed"
        exit 1
    fi
}

# Trigger deployment
trigger_deployment() {
    print_message "$BLUE" "🚀 Triggering new deployment..."
    
    # Create deployment
    DEPLOYMENT_ID=$(doctl apps create-deployment $APP_ID --format ID --no-header --wait)
    
    if [ -n "$DEPLOYMENT_ID" ]; then
        print_message "$GREEN" "✅ Deployment triggered: $DEPLOYMENT_ID"
        
        # Wait for deployment to complete
        print_message "$BLUE" "⏳ Waiting for deployment to complete..."
        
        # Monitor deployment status
        while true; do
            STATUS=$(doctl apps get-deployment $APP_ID $DEPLOYMENT_ID --format Phase --no-header)
            
            case $STATUS in
                "ACTIVE")
                    print_message "$GREEN" "✅ Deployment successful!"
                    break
                    ;;
                "ERROR"|"FAILED")
                    print_message "$RED" "❌ Deployment failed!"
                    # Show logs
                    print_message "$YELLOW" "📜 Deployment logs:"
                    doctl apps logs $APP_ID --type=build --tail=50
                    exit 1
                    ;;
                *)
                    echo -n "."
                    sleep 5
                    ;;
            esac
        done
    else
        print_message "$RED" "❌ Failed to trigger deployment"
        exit 1
    fi
}

# Get app logs
get_logs() {
    local log_type=${1:-run}
    local lines=${2:-100}
    
    print_message "$BLUE" "📜 Fetching $log_type logs (last $lines lines)..."
    doctl apps logs $APP_ID --type=$log_type --tail=$lines
}

# Set environment variables
set_env_vars() {
    print_message "$BLUE" "🔧 Setting environment variables..."
    
    # Read from .env.production if it exists
    if [ -f .env.production ]; then
        while IFS='=' read -r key value; do
            # Skip comments and empty lines
            [[ $key =~ ^#.*$ ]] && continue
            [[ -z $key ]] && continue
            
            # Remove quotes from value
            value="${value%\"}"
            value="${value#\"}"
            
            print_message "$YELLOW" "  Setting $key"
            doctl apps update $APP_ID --env "$key=$value"
        done < .env.production
        
        print_message "$GREEN" "✅ Environment variables updated"
    else
        print_message "$YELLOW" "⚠️  No .env.production file found"
    fi
}

# Scale app
scale_app() {
    local instances=${1:-1}
    
    print_message "$BLUE" "⚖️  Scaling app to $instances instances..."
    
    doctl apps update $APP_ID --spec .do/app.yaml
    
    print_message "$GREEN" "✅ App scaled to $instances instances"
}

# Rollback deployment
rollback() {
    print_message "$YELLOW" "⏪ Rolling back to previous deployment..."
    
    # Get previous active deployment
    PREV_DEPLOYMENT=$(doctl apps list-deployments $APP_ID --format "ID,Phase" --no-header | grep "SUPERSEDED" | head -1 | awk '{print $1}')
    
    if [ -n "$PREV_DEPLOYMENT" ]; then
        doctl apps create-deployment $APP_ID --deployment-id $PREV_DEPLOYMENT --wait
        print_message "$GREEN" "✅ Rolled back to deployment: $PREV_DEPLOYMENT"
    else
        print_message "$RED" "❌ No previous deployment found"
        exit 1
    fi
}

# Show app info
show_info() {
    print_message "$BLUE" "ℹ️  App Information"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "App Name: $APP_NAME"
    echo "App ID: $APP_ID"
    echo "GitHub Repo: $GITHUB_REPO"
    echo "Branch: $BRANCH"
    echo ""
    
    # Get live URL
    LIVE_URL=$(doctl apps get $APP_ID --format LiveURL --no-header)
    echo "Live URL: $LIVE_URL"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Get component info
    print_message "$BLUE" "📦 Components:"
    doctl apps list-components $APP_ID
}

# Monitor app
monitor_app() {
    print_message "$BLUE" "📊 Monitoring app metrics..."
    
    while true; do
        clear
        print_message "$GREEN" "=== App Monitor - $(date) ==="
        
        # Get app status
        echo ""
        print_message "$BLUE" "Status:"
        doctl apps get $APP_ID --format "ActiveDeployment.Phase,UpdatedAt" --no-header
        
        # Get recent logs
        echo ""
        print_message "$BLUE" "Recent logs:"
        doctl apps logs $APP_ID --type=run --tail=10
        
        echo ""
        print_message "$YELLOW" "Press Ctrl+C to exit"
        sleep 30
    done
}

# Main menu
show_menu() {
    echo ""
    print_message "$GREEN" "🚀 Digital Ocean App Platform Manager - $APP_NAME"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1) Deploy latest changes"
    echo "2) Update app specification"
    echo "3) Get app status"
    echo "4) View logs (run)"
    echo "5) View logs (build)"
    echo "6) Set environment variables"
    echo "7) Scale app"
    echo "8) Rollback deployment"
    echo "9) Monitor app (live)"
    echo "10) Show app info"
    echo "0) Exit"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -n "Select option: "
}

# Main function
main() {
    # Check prerequisites
    check_doctl
    authenticate
    
    # Handle command line arguments
    case "${1:-menu}" in
        deploy)
            trigger_deployment
            ;;
        update)
            update_app_spec
            ;;
        status)
            get_app_status
            ;;
        logs)
            get_logs "${2:-run}" "${3:-100}"
            ;;
        env)
            set_env_vars
            ;;
        scale)
            scale_app "${2:-1}"
            ;;
        rollback)
            rollback
            ;;
        info)
            show_info
            ;;
        monitor)
            monitor_app
            ;;
        menu|*)
            while true; do
                show_menu
                read -r option
                
                case $option in
                    1) trigger_deployment ;;
                    2) update_app_spec ;;
                    3) get_app_status ;;
                    4) get_logs "run" ;;
                    5) get_logs "build" ;;
                    6) set_env_vars ;;
                    7) 
                        echo -n "Number of instances: "
                        read -r instances
                        scale_app "$instances"
                        ;;
                    8) rollback ;;
                    9) monitor_app ;;
                    10) show_info ;;
                    0) 
                        print_message "$GREEN" "👋 Goodbye!"
                        exit 0
                        ;;
                    *) 
                        print_message "$RED" "Invalid option"
                        ;;
                esac
                
                echo ""
                echo -n "Press Enter to continue..."
                read -r
            done
            ;;
    esac
}

# Run main function
main "$@"