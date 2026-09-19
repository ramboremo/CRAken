from setuptools import setup, find_packages

setup(
    name="crascanner",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "crascanner=crascanner.cli:main",
        ],
    },
)
