from setuptools import setup, find_packages

with open("requirements.txt", encoding="utf-8") as f:
    requirements = f.read().splitlines()

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="canop",
    version="0.3.2",
    description="A fast, standalone security scanner designed to catch vulnerabilities written by AI.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="CanoP Security",
    author_email="canop.security@gmail.com",
    url="https://github.com/openbreach/canop",
    license="MIT",
    license_files=("LICENSE",),
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "canop=canop.cli:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
