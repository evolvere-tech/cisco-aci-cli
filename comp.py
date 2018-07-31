#!/usr/bin/env python

# ./compile.py build_ext --inplace
from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
ext_modules = [
    Extension("evoACI",  ["evoACI.py"]),
    Extension("migrations",  ["migrations.py"]),
]
setup(
    name = 'aciRunner',
    cmdclass = {'build_ext': build_ext},
    ext_modules = ext_modules
)
