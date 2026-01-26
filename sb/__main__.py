"""Entry point for python -m sb.cli"""
import os
import sys

# Clear malformed PYTHONWARNINGS before it causes issues
os.environ.pop('PYTHONWARNINGS', None)

# Suppress various warnings that don't affect functionality
import warnings
warnings.filterwarnings('ignore', category=RuntimeWarning, module='runpy')
warnings.filterwarnings('ignore', category=DeprecationWarning, module='urllib3')
warnings.filterwarnings('ignore', message='.*urllib3.*')

from .cli import main

if __name__ == '__main__':
    main()
