from setuptools import setup, find_packages

setup(
    name="wraith-net",
    version="1.0.0",
    author="Light (Neok1ra)",
    description="Attack Surface Intelligence Framework",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["rich>=13.0.0"],
    entry_points={
        "console_scripts": [
            "wraith-net=wraith_net.cli:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
