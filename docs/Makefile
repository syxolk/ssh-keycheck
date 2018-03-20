execution.png: execution.svg
	inkscape -z execution.svg -e execution.png
	optipng -quiet execution.png

execution.svg: execution.dot
	dot -Tsvg execution.dot -o execution.svg
