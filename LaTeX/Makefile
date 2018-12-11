.PHONY: tex all spellcheck

all: tex

tex:
	latexmk -pdf -pdflatex="pdflatex -interaction=nonstopmode" -use-make BachelorThesis.tex

spellcheck:
	find . -name "*.tex" -exec aspell --lang=en --mode=tex check "{}" \;
