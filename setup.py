from setuptools import setup, find_packages

setup(
    name="sorabbyngo-cml",
    version="1.0.0",
    description="Sorabbyngo Cognitive Mediation Layer",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.11",
    install_requires=[
        "nats-py>=2.6.0",
    ],
    extras_require={
        "suid": ["sorabbyngo-identity-core"],
    },
)
