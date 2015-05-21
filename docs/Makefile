all: html jd

html:
	mkdir -p html
	doxygen

jd:
	mkdir -p jd
	HTML_HEADER=header.jd HTML_OUTPUT=jd doxygen
	for file in jd/*.html; do echo mv "$${file}" "$${file/\.html/\.jd}"; done
