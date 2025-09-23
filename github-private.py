#!/usr/bin/env python3
"""
GitHub Repository Privacy Manager
Makes all your public repositories private
"""

import requests
import json
import sys
import time
from typing import List, Dict

class GitHubPrivacyManager:
    def __init__(self, token: str):
        self.token = token
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = 'https://api.github.com'
        self.username = None
        
    def authenticate(self) -> bool:
        """Verify authentication and get username"""
        try:
            response = requests.get(f'{self.base_url}/user', headers=self.headers)
            if response.status_code == 200:
                user_data = response.json()
                self.username = user_data['login']
                print(f"✅ Authenticated as: {self.username}")
                print(f"   Name: {user_data.get('name', 'N/A')}")
                print(f"   Public repos: {user_data.get('public_repos', 0)}")
                print(f"   Private repos: {user_data.get('total_private_repos', 'N/A')}")
                return True
            else:
                print(f"❌ Authentication failed: {response.status_code}")
                print(f"   {response.json().get('message', 'Unknown error')}")
                return False
        except Exception as e:
            print(f"❌ Error during authentication: {e}")
            return False
    
    def get_public_repos(self) -> List[Dict]:
        """Get all public repositories for the authenticated user"""
        public_repos = []
        page = 1
        
        while True:
            try:
                response = requests.get(
                    f'{self.base_url}/user/repos',
                    headers=self.headers,
                    params={
                        'visibility': 'public',
                        'per_page': 100,
                        'page': page,
                        'type': 'owner'
                    }
                )
                
                if response.status_code != 200:
                    print(f"❌ Failed to fetch repositories: {response.status_code}")
                    break
                
                repos = response.json()
                if not repos:
                    break
                
                public_repos.extend(repos)
                page += 1
                
            except Exception as e:
                print(f"❌ Error fetching repositories: {e}")
                break
        
        return public_repos
    
    def make_repo_private(self, repo_name: str) -> bool:
        """Make a single repository private"""
        try:
            response = requests.patch(
                f'{self.base_url}/repos/{self.username}/{repo_name}',
                headers=self.headers,
                json={'private': True}
            )
            
            if response.status_code == 200:
                return True
            else:
                print(f"   Error: {response.json().get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"   Exception: {e}")
            return False
    
    def make_all_private(self):
        """Main function to make all repositories private"""
        print("\n🔍 Fetching public repositories...")
        public_repos = self.get_public_repos()
        
        if not public_repos:
            print("✅ No public repositories found! All repos are already private.")
            return
        
        print(f"\n📊 Found {len(public_repos)} public repositories:\n")
        for repo in public_repos:
            print(f"  📂 {repo['name']}")
            if repo.get('fork'):
                print(f"     ⚠️  This is a fork")
            if repo.get('archived'):
                print(f"     ⚠️  This is archived")
        
        print(f"\n⚠️  Warning: This will make ALL {len(public_repos)} repositories private!")
        confirm = input("Do you want to continue? (yes/no): ").strip().lower()
        
        if confirm != 'yes':
            print("❌ Operation cancelled")
            return
        
        print("\n🔒 Making repositories private...\n")
        
        success_count = 0
        failed_count = 0
        failed_repos = []
        
        for repo in public_repos:
            repo_name = repo['name']
            print(f"  Processing {repo_name}... ", end='')
            
            # Skip if it's already being processed
            if repo.get('private'):
                print("Already private ✓")
                continue
            
            if self.make_repo_private(repo_name):
                print("✅ Success!")
                success_count += 1
            else:
                print("❌ Failed!")
                failed_count += 1
                failed_repos.append(repo_name)
            
            # Rate limiting - GitHub allows 5000 requests per hour
            time.sleep(0.5)  # Small delay to avoid hitting rate limits
        
        print("\n" + "="*50)
        print("📈 Summary:")
        print(f"  ✅ Successfully made private: {success_count}")
        print(f"  ❌ Failed: {failed_count}")
        
        if failed_repos:
            print("\n❌ Failed repositories:")
            for repo in failed_repos:
                print(f"  - {repo}")
            print("\nNote: Repos might fail if:")
            print("  - They are forks (need to be detached first)")
            print("  - You don't have admin access")
            print("  - You've reached private repo limits")
        
        print("\n✅ Operation completed!")

def main():
    print("🔒 GitHub Repository Privacy Manager")
    print("="*50)
    
    # Check if token is provided as argument
    if len(sys.argv) > 1:
        token = sys.argv[1]
    else:
        print("\nPlease provide your GitHub Personal Access Token")
        print("\nTo create a token:")
        print("1. Go to: https://github.com/settings/tokens")
        print("2. Click 'Generate new token (classic)'")
        print("3. Select scope: 'repo' (Full control)")
        print("4. Generate and copy the token\n")
        token = input("Enter your GitHub token: ").strip()
    
    if not token:
        print("❌ No token provided")
        sys.exit(1)
    
    # Create manager and run
    manager = GitHubPrivacyManager(token)
    
    if manager.authenticate():
        manager.make_all_private()
    else:
        print("\n❌ Failed to authenticate. Please check your token.")
        sys.exit(1)

if __name__ == "__main__":
    main()