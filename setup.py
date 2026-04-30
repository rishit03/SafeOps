from setuptools import setup, find_packages


setup(
    name="safeops",
    version="0.1.0",
    description="SafeOps - Security posture and exposure scanner for startups",
    author="Rishit",
    packages=find_packages(),
    install_requires=[
        "requests"
    ],
    entry_points={
        "console_scripts": [
            "safeops=safeops.main:main"
        ]
    },
    python_requires=">=3.9",
)