from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="canop",
    version="0.1.0",
    description="A fast, standalone security scanner designed to catch vulnerabilities written by AI.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="CanoP Security",
    author_email="canop.security@gmail.com",
    url="https://github.com/openbreach/canop",
    packages=find_packages(),
    include_package_data=True,  # Important so that it bundles your YAML rules
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "canop=canop.cli:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
