"""Setup configuration for Agent Scrutiny - Python SDK.

Dependencies are read from requirements.txt and requirements-dev.txt rather
than being hard-coded here. This keeps the requirements files as the single
source of truth for what the SDK depends on, regardless of how it gets
installed (pip install -r requirements.txt, pip install -e ., or
pip install -e ".[dev]").
"""

from pathlib import Path

from setuptools import find_packages, setup

# ---------------------------------------------------------------------------
# Paths and helpers
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent


def parse_requirements(filename: str) -> list[str]:
    """
    Parse a pip requirements file into a list of install_requires strings.

    Skips blank lines, comments (both whole-line and inline), and pip
    directives that setup.py cannot interpret. Specifically:

        * Lines starting with '#' are skipped (whole-line comments).
        * Anything after '#' on a line is stripped (inline comments).
        * Lines starting with '-' are skipped (pip directives like
          -r requirements.txt, -e ., --index-url, --extra-index-url, etc.).

    Environment markers (e.g. 'pydantic>=2.5.0; python_version >= "3.9"')
    are preserved — setuptools understands them.
    """
    requirements: list[str] = []
    with (ROOT / filename).open(encoding="utf-8") as f:
        for raw_line in f:
            # Strip inline comments and surrounding whitespace.
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("-"):
                # pip directive — setup.py does not interpret these.
                continue
            requirements.append(line)
    return requirements


# ---------------------------------------------------------------------------
# Read project metadata and dependencies
# ---------------------------------------------------------------------------

long_description = (ROOT / "README.md").read_text(encoding="utf-8")

install_requirements = parse_requirements("requirements.txt")
dev_requirements = parse_requirements("requirements-dev.txt")


# ---------------------------------------------------------------------------
# setup()
# ---------------------------------------------------------------------------

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
    install_requires=install_requirements,
    extras_require={
        "dev": dev_requirements,
    },
    entry_points={
        "console_scripts": [
            "agent-scrutiny=agent_scrutiny.cli:main",  # CLI lands in Stage 1+
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