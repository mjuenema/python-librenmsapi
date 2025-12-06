

all:
	@echo "make code"
	@echo "make test"
	@echo "make build"
	@echo "make publish"
	@echo "make testpublish"



code:
	./generate.py > librenmsapi.py
	python -m black --verbose librenmsapi.py




test: code
	make -C tests test

retest: code
	make -C tests retest

debug: code
	make -C tests debug

redebug: code
	make -C tests redebug


build: test
	flit build --setup-py --format wheel
	flit build --setup-py --format sdist


testpublish: build
	flit publish --repository=testpypi --setup-py --format wheel
	flit publish --repository=testpypi --setup-py --format sdist

publish: build
	flit publish --repository=pypi --setup-py --format wheel
	flit publish --repository=pypi --setup-py --format sdist
