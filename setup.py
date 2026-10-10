from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = [l.strip() for l in f if l.strip() and not l.startswith("#")]

setup(
    name="outscan",
    version="1.0.0",
    description="OutSystems Platform Security Scanner — based on original 0-day research",
    long_description=(
        "OutScan is a security scanner purpose-built for OutSystems Platform Server 11.x. "
        "It detects architectural security flaws including viewName authorization bypass (CWE-863), "
        "model.js entity schema exposure (CWE-200), admin panel exposure, CORS misconfigurations, "
        "and OIDC/OAuth secret exposure. Based on original 0-day research by Adrian Martinez."
    ),
    author="Adrian Martinez",
    author_email="me@adrianmartinez.lat",
    url="https://github.com/Bl4ckSkul1/outscan",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "outscan=os_scanner.main:main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords=[
        "outsystems", "security", "pentest", "vulnerability-scanner",
        "appsec", "owasp", "authorization-bypass", "0day",
    ],
)
