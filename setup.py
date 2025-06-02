from setuptools import setup, find_packages
from pathlib import Path

# Find .whl files in the packages directory
packages_dir = Path('packages')
dependency_links = []
install_requires = []

if packages_dir.exists():
    for whl in packages_dir.glob('*.whl'):
        # Format: name-version-...whl
        name = whl.stem.split('-')[0]
        dependency_links.append(f'file:{whl}')
        install_requires.append(name)

setup(
    name='fractum',
    version='1.2.0',
    packages=find_packages(),
    install_requires=install_requires,
    dependency_links=dependency_links,
    setup_requires=['wheel'],
    entry_points={
        'console_scripts': [
            'fractum=src.__init__:cli',
        ],
    },
    python_requires='==3.12.10',
)