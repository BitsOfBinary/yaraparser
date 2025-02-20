import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="yaraparser",
    version="0.0.1",
    author="BitsOfBinary",
    description="Python 3 tool to parse Yara rules (extension of yarabuilder)",
    long_description=long_description,
    test_suite="tests",
    url="https://github.com/BitsOfBinary/yaraparser",
    packages=setuptools.find_packages(exclude=['docs', 'tests']),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        'yarabuilder'
    ],
    entry_points={
        'console_scripts': [
            'yaraparser=yaraparser.app:main',
        ],
    },
)