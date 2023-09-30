from setuptools import setup, find_packages

setup(
    name='py_nessus_pro',
    version='0.6',
    packages=find_packages(),
    install_requires=[
        'selenium',
        'beautifulsoup4',
        'slugify',
    ],
    author='Matbe34',
    description='Python library for managing Nessus Professional.',
    long_description=open('README.md').read(),
    url='https://github.com/Matbe34/py_nessus',
    classifiers=['Programming Language :: Python :: 3']
)
