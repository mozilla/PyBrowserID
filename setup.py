
import os
import sys
from setuptools import setup, find_packages

setup_kwds = {}
if sys.version_info > (3,):
    setup_kwds["use_2to3"] = True

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    README = f.read()

with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = ['requests']

tests_require = requires + ['mock']

setup(name='PyBrowserID',
      version='0.9.0',
      description='Python library for the BrowserID Protocol',
      long_description=README + '\n\n' + CHANGES,
      license='MPLv2.0',
      classifiers=[
        "Programming Language :: Python",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        ],
      author='Mozilla Identity Team',
      author_email='dev-identity@lists.mozilla.org',
      url='https://github.com/mozilla/PyBrowserID',
      keywords='authentication browserid login email',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=tests_require,
      test_suite="browserid.tests",
      **setup_kwds)
