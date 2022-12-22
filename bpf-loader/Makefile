.PHONY: install coverage test docs help generate_tools
.DEFAULT_GOAL := install

define BROWSER_PYSCRIPT
import os, webbrowser, sys

try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"
INSTALL_LOCATION := ~/.local

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

install-deps: ## install deps
	apt update
	apt-get install libcurl4-openssl-dev libelf-dev clang llvm -y ## libgtest-dev

Catch2:
	git clone https://github.com/catchorg/Catch2.git --depth=1
	cd Catch2 && cmake -Bbuild -H. -DBUILD_TESTING=OFF
	cd Catch2 && sudo cmake --build build/ --target install
	sudo apt install lcov -y

test: Catch2 ## run tests quickly with ctest
	sudo rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -Deunomia_ENABLE_UNIT_TESTING=1 -Deunomia_ENABLE_ASAN=1 -Deunomia_ENABLE_CODE_COVERAGE=1
	cmake --build build
	cd build/ && sudo ctest -VV

coverage: ## check code coverage quickly GCC
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -Deunomia_ENABLE_CODE_COVERAGE=1
	cmake --build build --config Release
	cd build/ && sudo ctest -C Release -VV
	cd .. && (bash -c "find . -type f -name '*.gcno' -exec gcov -pb {} +" || true)

docs: ## generate Doxygen HTML documentation, including API docs
	rm -rf docs/
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -Deunomia_ENABLE_DOXYGEN=1 -DCMAKE_BUILD_TYPE=Release
	cmake --build build --target doxygen-docs
	mkdir docs/html/doc/
	cp -r doc/imgs docs/html/
	cp -r doc/imgs docs/html/doc/
	$(BROWSER) docs/html/index.html

install: ## install the package to the `INSTALL_LOCATION`
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -DCMAKE_BUILD_TYPE=Release
	cmake --build build --config Release
	cmake --build build --target install --config Release

build-cmd:
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -DCMAKE_BUILD_TYPE=Release -Deunomia_BUILD_EXECUTABLE=1
	cmake --build build --config Release

format: ## format the project sources
	cmake -Bbuild
	cmake --build build --target clang-format

clean: ## clean the project build files
	rm -rf build/
	rm -rf docs/
