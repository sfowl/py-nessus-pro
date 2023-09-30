from setuptools import setup, find_packages

setup(
    name='py_nessus_pro',
    version='0.5',
    packages=find_packages(),
    install_requires=[
        'selenium',
        'beautifulsoup4',
        'slugify',
    ],
    author='Matbe34',
    description='Python library for managing Nessus Professional.',
    long_description='Python library for managing Nessus Professional that provides an interface to interactuate with the API allowing to create, launch, monitor and manage scans.',
    url='https://github.com/Matbe34/py_nessus',
    classifiers=['Programming Language :: Python :: 3']
)
