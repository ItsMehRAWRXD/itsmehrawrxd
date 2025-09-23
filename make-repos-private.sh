#!/bin/bash

# Script to make all GitHub repositories private
# Usage: ./make-repos-private.sh <github-token>

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔒 GitHub Repository Privacy Script"
echo "===================================="

# Check if token is provided
if [ -z "$1" ]; then
    echo -e "${YELLOW}Please provide your GitHub personal access token${NC}"
    echo ""
    echo "To create a token:"
    echo "1. Go to https://github.com/settings/tokens"
    echo "2. Click 'Generate new token (classic)'"
    echo "3. Select scopes: 'repo' (full control)"
    echo "4. Generate and copy the token"
    echo ""
    echo "Usage: ./make-repos-private.sh YOUR_GITHUB_TOKEN"
    exit 1
fi

GITHUB_TOKEN=$1

# Authenticate with GitHub CLI
echo -e "${YELLOW}Authenticating with GitHub...${NC}"
echo $GITHUB_TOKEN | gh auth login --with-token

if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to authenticate with GitHub${NC}"
    exit 1
fi

# Get GitHub username
USERNAME=$(gh api user --jq .login)
echo -e "${GREEN}Authenticated as: $USERNAME${NC}"
echo ""

# List all public repositories
echo -e "${YELLOW}Fetching all public repositories...${NC}"
PUBLIC_REPOS=$(gh repo list $USERNAME --public --limit 1000 --json name,isPrivate,url | jq -r '.[] | select(.isPrivate == false) | .name')

if [ -z "$PUBLIC_REPOS" ]; then
    echo -e "${GREEN}No public repositories found. All repos are already private!${NC}"
    exit 0
fi

# Count repositories
REPO_COUNT=$(echo "$PUBLIC_REPOS" | wc -l)
echo -e "${YELLOW}Found $REPO_COUNT public repositories${NC}"
echo ""

# List repositories
echo "Public repositories to be made private:"
echo "----------------------------------------"
echo "$PUBLIC_REPOS" | while read repo; do
    echo "  📂 $repo"
done
echo ""

# Ask for confirmation
read -p "Do you want to make ALL these repositories private? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo -e "${YELLOW}Operation cancelled${NC}"
    exit 0
fi

echo ""
echo -e "${YELLOW}Making repositories private...${NC}"
echo ""

# Make each repository private
SUCCESS_COUNT=0
FAIL_COUNT=0
FAILED_REPOS=""

echo "$PUBLIC_REPOS" | while read repo; do
    if [ -n "$repo" ]; then
        echo -n "  Making $repo private... "
        
        # Use GitHub API to make repo private
        gh api \
            --method PATCH \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            /repos/$USERNAME/$repo \
            -f private=true > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓${NC}"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            echo -e "${RED}✗${NC}"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            FAILED_REPOS="$FAILED_REPOS$repo\n"
        fi
    fi
done

echo ""
echo "===================================="
echo -e "${GREEN}Summary:${NC}"
echo "  Successfully made private: $SUCCESS_COUNT"
if [ $FAIL_COUNT -gt 0 ]; then
    echo -e "  ${RED}Failed: $FAIL_COUNT${NC}"
    echo ""
    echo "Failed repositories:"
    echo -e "$FAILED_REPOS"
    echo ""
    echo "Note: Some repos might fail if:"
    echo "  - You don't have admin access"
    echo "  - You're on a free plan (limited private repos for organizations)"
    echo "  - The repository is a fork"
fi

echo ""
echo -e "${GREEN}✅ Operation completed!${NC}"

# Verify the changes
echo ""
echo -e "${YELLOW}Verifying changes...${NC}"
REMAINING_PUBLIC=$(gh repo list $USERNAME --public --limit 1000 --json name | jq -r '.[].name' | wc -l)

if [ "$REMAINING_PUBLIC" -eq 0 ]; then
    echo -e "${GREEN}✓ All repositories are now private!${NC}"
else
    echo -e "${YELLOW}⚠ You still have $REMAINING_PUBLIC public repositories${NC}"
fi