from setuptools import setup, find_packages

setup(
    name='py_nessus',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'selenium',
        'beautifulsoup4',
        'slugify',
    ],
    author='Matbe34',
    description='Python library for Nessus Professional that provides an nterface to interactuate with the API allowing to create, launch and manage scans.',
    long_description=open('README.md').read(),
    url='https://github.com/Matbe34/py_nessus',
    classifiers=['Programming Language :: Python :: 3']
)
