#!/usr/bin/env python3
"""
Security Cleanup & Deployment Guide
====================================
This script guides you through the steps to complete the security fix.
"""

import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a command and report status"""
    print(f"\n{'='*60}")
    print(f"📋 {description}")
    print(f"{'='*60}")
    print(f"Command: {cmd}\n")
    
    result = subprocess.run(cmd, shell=True)
    return result.returncode == 0

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     CYBERSICKER SECURITY CLEANUP & DEPLOYMENT GUIDE         ║
║                                                              ║
║  This guide will help you complete the security remediation ║
║  for the leaked Gemini API key.                             ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    print("""
⚠️  CRITICAL FIRST STEP - REVOKE THE LEAKED API KEY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The leaked API key needs to be revoked immediately:

1. Go to→ https://aistudio.google.com/apikey

2. Find and DELETE the key:
   AIzaSyAzbsbhpuIDd_Zcphg5747cLBQBF1qIgfE

3. Generate a NEW API key

4. Save the new key securely

⏸️  PRESS ENTER once you have revoked the old key and 
        generated a new one...
    """)
    input()
    
    api_key = input("\n🔑 Enter your NEW Gemini API key: ").strip()
    if not api_key:
        print("❌ API key is required!")
        sys.exit(1)
    
    # Create/update .env file
    env_file = ".env"
    with open(env_file, "w") as f:
        f.write(f"# Gemini API Configuration\n")
        f.write(f"GEMINI_API_KEY={api_key}\n")
    print(f"✅ Created/updated {env_file} with new API key")
    
    # Verify git status
    print("\n" + "="*60)
    print("📊 Current Git Status")
    print("="*60)
    subprocess.run("git status", shell=True)
    
    # Show what will be pushed
    print("\n" + "="*60)
    print("📈 Commits to be pushed (cleaned history)")
    print("="*60)
    subprocess.run("git log --oneline origin/main..main 2>/dev/null || git log --oneline -10", shell=True)
    
    print("""
    
✅ READY TO PUSH
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The repository is ready for deployment. The cleaned history will:

  ✓ Remove all instances of the leaked API key
  ✓ Replace with [REDACTED_LEAKED_API_KEY]
  ✓ Maintain commit history and messages
  ✓ Update cyber_test.py to use environment variables

⚠️  WARNING: Force-pushing rewrites repository history!
            Only proceed if you have admin access.

⏸️  Press ENTER to push, or Ctrl+C to cancel...
    """)
    input()
    
    # Push the cleaned history
    print("\n" + "="*60)
    print("🚀 Pushing cleaned history to GitHub...")
    print("="*60 + "\n")
    
    cmd = "git push origin main --force-with-lease"
    success = run_command(cmd, "Force-push cleaned history")
    
    if success:
        print("""
        
╔══════════════════════════════════════════════════════════════╗
║                   ✅ SUCCESS!                               ║
║                                                              ║
║  Security remediation is complete! Here's what was done:   ║
║                                                              ║
║  ✓ Revoked leaked API key                                  ║
║  ✓ Generated new API key                                   ║
║  ✓ Created .env file with new credentials                 ║
║  ✓ Pushed cleaned git history                             ║
║  ✓ Removed hardcoded credentials from code                ║
║  ✓ Added .gitignore to prevent future leaks               ║
║                                                              ║
║  NEXT STEPS:                                                ║
║  1. Verify push succeeded on GitHub                        ║
║  2. Close the GitScan issue                                ║
║  3. Share setup instructions with team:                    ║
║                                                              ║
║     export GEMINI_API_KEY="your_new_key_here"              ║
║     python cyber_test.py                                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)
    else:
        print("""
        
❌ Push failed. Possible reasons:
   • Authentication error - check GitHub credentials
   • Repository access - ensure you have admin permissions
   • Network issue - check your internet connection
   
Try manually:
   git push origin main --force-with-lease
        """)
        sys.exit(1)

if __name__ == "__main__":
    main()
