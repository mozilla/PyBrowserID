
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    README = f.read()

with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = ['M2Crypto']

setup(name='PyVEP',
      version='0.3.1',
      description='Python library for the Verified Email Protocol',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
        "Programming Language :: Python",
        ],
      author='Mozilla Identity Team',
      author_email='dev-identity@lists.mozilla.org',
      url='https://github.com/mozilla/PyVEP',
      keywords='authentication vep browserid login email',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="vep")
