"""Setup configuration for Agent Scrutiny - Python SDK."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="agent-scrutiny",
    version="0.1.0-dev",
    author="Zero-Trust AI Contributors",
    author_email="contact@zero-trust.ai",
    license="MIT",
    description="Agent Scrutiny - Zero-trust security for AI agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zero-trust-ai/agent-scrutiny-python",
    project_urls={
        "Documentation": "https://agent-scrutiny.com/docs",
        "Source": "https://github.com/zero-trust-ai/agent-scrutiny-python",
        "Tracker": "https://github.com/zero-trust-ai/agent-scrutiny-python/issues",
        "Homepage": "https://zero-trust.ai",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=[
        "python-dotenv>=1.0.0",
        "pydantic>=2.5.0",
        "typing-extensions>=4.9.0",
        "structlog>=24.1.0",
        "colorama>=0.4.6",
        "pyyaml>=6.0.1",
        "cryptography>=41.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.12.0",
            "black>=23.12.0",
            "isort>=5.13.0",
            "flake8>=7.0.0",
            "mypy>=1.8.0",
            "pylint>=3.0.0",
            "sphinx>=7.2.0",
            "sphinx-rtd-theme>=2.0.0",
            "myst-parser>=2.0.0",
            "ipython>=8.19.0",
            "ipdb>=0.13.13",
            "pre-commit>=3.6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "agent-scrutiny=agent_scrutiny.cli:main",  # Will be implemented in Stage 1
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        "ai-security",
        "zero-trust",
        "llm-security",
        "agent-security",
        "agent-scrutiny",
        "prompt-injection",
        "mcp-security",
        "artificial-intelligence",
    ],
)
