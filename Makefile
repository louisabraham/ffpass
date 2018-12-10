pypi: dist
	twine upload dist/*
	
dist: doc flake8
	-rm dist/*
	./setup.py sdist bdist_wheel

flake8:
	flake8 . --count --select=E901,E999,F821,F822,F823 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

clean:
	rm -rf *.egg-info build dist

doc: README.md
	pandoc README.md -o README.rst