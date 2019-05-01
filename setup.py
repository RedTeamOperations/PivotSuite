from setuptools import setup , find_packages

setup(
    name='pivotsuite',
    version='1.0',
    packages= find_packages(),
    url='https://github.com/RedTeamOperations/PivotSuite',
    license='GPL v3',
    author='Manish Gupta',
    author_email='admin@myhacker.online',
    description='PivotSuite : A Network Pivoting Toolkit',
    long_description=open('README.md').read(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Red Teamers/Penetration Tester",
        "GNU Lesser General Public License v2 or later (LGPLv2+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Topic :: System :: Networking",
    ],
    entry_points={
        'console_scripts': [
            'pivotsuite = pivot_suite.pivotsuite:main',
        ],
    },

)
