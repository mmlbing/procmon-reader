"""Build configuration for procmon-reader.

Build:
    pip install -e .

Or build in-place for development:
    python setup.py build_ext --inplace
"""

import sys
import pybind11
from setuptools import setup, Extension
from setuptools.command.build_py import build_py


class BuildPyWithoutCpp(build_py):
    """Exclude C++ source/header files from the wheel (they belong in sdist only)."""
    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        return [(pkg, mod, path) for pkg, mod, path in modules
                if not path.endswith(('.cpp', '.h'))]

    def build_package_data(self):
        """Filter out .cpp/.h files from package data before copying."""
        super().build_package_data()
        # Remove any .cpp/.h files that were copied to build_lib
        import os
        for root, dirs, files in os.walk(self.build_lib):
            for f in files:
                if f.endswith(('.cpp', '.h')):
                    os.remove(os.path.join(root, f))

extra_compile_args = []
extra_link_args = []

if sys.platform == 'win32':
    extra_compile_args = ['/std:c++17', '/O2', '/EHsc']
else:
    # -pthread is required for std::thread on Linux/macOS GCC/Clang
    extra_compile_args = ['-std=c++17', '-O2', '-pthread']
    extra_link_args = ['-pthread']

_pml_core = Extension(
    'procmon_reader._pml_core',
    sources=[
        'procmon_reader/cpp/_pml_core.cpp',
        'procmon_reader/cpp/pml_reader.cpp',
        'procmon_reader/cpp/procmon_reader.cpp',
        'procmon_reader/cpp/pml_filter_core.cpp',
        'procmon_reader/cpp/pml_detail_registry.cpp',
        'procmon_reader/cpp/pml_detail_filesystem.cpp',
        'procmon_reader/cpp/pml_detail_process.cpp',
        'procmon_reader/cpp/pml_detail_network.cpp',
    ],
    include_dirs=[pybind11.get_include(), 'procmon_reader/cpp'],
    depends=[
        'procmon_reader/cpp/pml_consts.h',
        'procmon_reader/cpp/pml_detail.h',
        'procmon_reader/cpp/pml_detail_common.h',
        'procmon_reader/cpp/pml_enums.h',
        'procmon_reader/cpp/pml_filter_core.h',
        'procmon_reader/cpp/pml_format.h',
        'procmon_reader/cpp/pml_preprocess.h',
        'procmon_reader/cpp/pml_reader.h',
        'procmon_reader/cpp/pml_types.h',
        'procmon_reader/cpp/pml_utils.h',
        'procmon_reader/cpp/procmon_reader.h',
    ],
    extra_compile_args=extra_compile_args,
    extra_link_args=extra_link_args,
    language='c++',
)

setup(
    ext_modules=[_pml_core],
    cmdclass={'build_py': BuildPyWithoutCpp},
)
