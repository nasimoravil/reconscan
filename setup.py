from setuptools import setup, find_packages

setup(
    name="reconscan",
    version="0.1.0",
    description="Advanced Web & JavaScript Reconnaissance Tool (rule-based, no AI)",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "reconscan=reconscan.cli:main",
        ],
    },
    python_requires=">=3.8",
)
