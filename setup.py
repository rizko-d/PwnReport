"""Compatibility setup entry point for older pip/setuptools versions."""

from pathlib import Path

from setuptools import find_packages, setup


root = Path(__file__).parent
long_description = (root / "README.md").read_text(encoding="utf-8")

setup(
    name="pwnreport",
    version="0.4.0",
    description="JSON-first penetration test finding and report manager",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Rizko Febri Rachmayadi",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages("src"),
    python_requires=">=3.9",
    entry_points={"console_scripts": ["pwnreport=pwnreport.cli:main"]},
)
