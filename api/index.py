import os
import sys

# Ensure the root directory is in the path so we can import 'web'
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from web import app

# This is the entry point for Vercel
# Vercel looks for a variable called 'app' in the entry file
