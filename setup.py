from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="sentinelrecon",
    version="1.0.0",
    author="SentinelRecon Team",
    author_email="team@sentinelrecon.dev",
    description="AI-Powered Intelligent Reconnaissance Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sentinelrecon/sentinelrecon",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking",
        "Topic :: Internet",
    ],
    python_requires=">=3.9",
    install_requires=[
        "click==8.1.7",
        "scapy==2.5.0",
        "requests==2.31.0",
        "anthropic==0.25.0",
        "sqlalchemy==2.0.29",
        "jinja2==3.1.3",
        "weasyprint==61.2",
        "python-dotenv==1.0.1",
        "cryptography==42.0.5",
        "rich==13.7.1",
        "tqdm==4.66.2",
        "flask==3.0.3",
    ],
    entry_points={
        "console_scripts": [
            "sentinelrecon=sentinelrecon.cli.main:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
