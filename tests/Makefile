

test: test38 test39 test310 test311 test312 test313 test314 test315

test38:
	PYTHONPATH='..' uv run --python 3.8 pytest -v -x tests.py

test39:
	PYTHONPATH='..' uv run --python 3.9 pytest -v -x tests.py

test310:
	PYTHONPATH='..' uv run --python 3.10 pytest -v -x tests.py

test311:
	PYTHONPATH='..' uv run --python 3.11 pytest -v -x tests.py

test312:
	PYTHONPATH='..' uv run --python 3.12 pytest -v -x tests.py

test313:
	PYTHONPATH='..' uv run --python 3.13 pytest -v -x tests.py

test314:
	PYTHONPATH='..' uv run --python 3.14 pytest -v -x tests.py

test315:
	PYTHONPATH='..' uv run --python 3.15 pytest -v -x tests.py

retest:
	PYTHONPATH='..' pytest --lf -v -x tests.py

debug:
	PYTHONPATH='..' pytest -v -x --pdb tests.py

redebug:
	PYTHONPATH='..' pytest --lf -v -x --pdb tests.py
