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
    long_description="A Network Pivoting Toolkit for Red Teamers / Penetration Testers. "
                     "For More Informations Visit: https://github.com/RedTeamOperations/PivotSuite",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking",
    ],
    entry_points={
        'console_scripts': [
            'pivotsuite = pivot_suite.pivotsuite:main',
        ],
    },

)