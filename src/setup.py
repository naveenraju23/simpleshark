import os
import setuptools

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as f:
    long_description = f.read()

setuptools.setup(
    name="simpleshark",
    version="0.0.8",
    author="Naveen Raju",
    author_email="naveen.raju23@gmail.com",
    package_data={'': ['*.ini']},
    packages=setuptools.find_packages(),
    install_requires=['lxml', 'py'],
    url="https://github.com/naveenraju23/simpleshark",
    long_description=long_description,
    long_description_content_type="text/markdown",
    description="Python package to parse tshark/wireshark/tcpdump captured pcaps and return python objects.",
    keywords="wireshark packets parsing pcap packets",
    classifiers=[
        'Programming Language :: Python :: 3',
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.5'
)
