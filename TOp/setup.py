#!/usr/bin/env python3
"""
Wireless Network Analysis Framework - Installation Script
"""

import os
import sys
from setuptools import setup, find_packages

# Check for Python version
if sys.version_info < (3, 8):
    sys.exit('Python >= 3.8 is required for this framework')

# Check for root privileges for the installation of certain dependencies
if os.geteuid() != 0 and not any('--user' in arg for arg in sys.argv):
    print("NOTE: Installing without root privileges. Some system-level dependencies")
    print("      may need to be installed separately using your system package manager.")
    print("      For a full installation, run as root or use --user flag.")
    print("\nProceeding with installation...\n")

# Get long description from README
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

# Core dependencies - always required
core_dependencies = [
    'scapy>=2.4.5',    # For packet manipulation
    'pyric>=0.1.6.3',  # For wireless interface control
    'netifaces>=0.11.0',  # For interface information
    'pyroute2>=0.6.7', # For netlink socket communication
    'tabulate>=0.8.9', # For formatted table output
    'cryptography>=36.0.0', # For security operations
]

# Optional dependencies - installed when specified
ml_dependencies = [
    'numpy>=1.20.0',
    'pandas>=1.3.0',
    'scikit-learn>=1.0.0',
]

torch_dependencies = [
    'torch>=1.10.0',
]

visualization_dependencies = [
    'matplotlib>=3.5.0',
    'seaborn>=0.11.2',
]

dev_dependencies = [
    'pytest>=7.0.0',
    'pytest-cov>=2.12.0',
    'mypy>=0.910',
    'black>=21.12b0',
    'isort>=5.10.0',
    'pylint>=2.12.0',
]

# All dependencies
all_dependencies = (
    core_dependencies +
    ml_dependencies +
    torch_dependencies +
    visualization_dependencies
)

# Setup configuration
setup(
    name='wireless-network-analysis-framework',
    version='0.1.0',
    description='Advanced Wireless Network Analysis Framework for Security Research',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Security Research Team',
    author_email='research@example.com',
    url='https://github.com/example/wireless-analysis-framework',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Monitoring',
    ],
    python_requires='>=3.8',
    install_requires=core_dependencies,
    extras_require={
        'ml': ml_dependencies,
        'torch': torch_dependencies,
        'viz': visualization_dependencies,
        'dev': dev_dependencies,
        'all': all_dependencies,
    },
    entry_points={
        'console_scripts': [
            'wnaf=framework.main:main',
        ],
    },
    include_package_data=True,
    package_data={
        'framework': [
            'data/vendor_db.json',
            'data/configs/*.json',
        ],
    },
    # Compile native extensions if available
    ext_modules=[],
    # Scripts for post-installation setup
    scripts=[
        'scripts/check_dependencies.py',
        'scripts/setup_monitor_mode.sh',
    ],
    zip_safe=False,
)