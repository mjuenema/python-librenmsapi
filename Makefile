

all:
	@echo "make code         - Create librenmsapi.py"
	@echo "make clean        - Delete librenmsapi.py"
	@echo "make test"
	@echo "make build"
	@echo "make publish"
	@echo "make testpublish"



code:
	./generate.py > librenmsapi.py
	python -m black --verbose librenmsapi.py

clean:
	rm -v librenmsapi.py


test: code
	make -C tests test

retest: code
	make -C tests retest

debug: code
	make -C tests debug

redebug: code
	make -C tests redebug


build: test
	flit build --format wheel
	flit build --format sdist


testpublish: build
	flit publish --repository=testpypi --format wheel
	flit publish --repository=testpypi --format sdist

publish: build
	flit publish --repository=librenms --format wheel
	flit publish --repository=librenms --format sdist
