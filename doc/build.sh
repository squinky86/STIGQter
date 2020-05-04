#!/bin/bash

function exists {
	which "$1" > /dev/null 2> /dev/null
	ret=$?
	#program doesn't exist; check if aliased
	if [ $ret -gt 0 ]; then
		if [ -z "$2" ]; then
			echo "Checking alias for $1..."
		fi
		type -a "$1" > /dev/null 2> /dev/null
		ret=$?
	fi
	if [ $ret -gt 0 ]; then
		if [ -z "$2" ]; then
			echo "Please install ${1} before building the documentation."
			exit 1
		fi
		return 1
	fi
	return 0
}

function lbll {
	echo -n "Building $1..."
	buf=$(mktemp)
	lualatex -interaction=nonstopmode "$1" >> $buf && biber "$1" >> $buf && lualatex -interaction=nonstopmode "$1" >> $buf && lualatex -interaction=nonstopmode "$1" >> $buf
	if [ $? -eq 0 ]; then
		echo "OK!"
	else
		echo "FAILED!"
		tail -n 100 $buf
	fi
	if exists pdfsizeopt 1; then
		echo -n "Compressing $1..."
		OPTS=""
		if exists pngwolf 1; then
			OPTS="--use-image-optimizer=pngwolf"
		fi
		if exists advpng 1; then
			OPTS="${OPTS} --use-image-optimizer=advpng4"
		fi
		pdfsizeopt $OPTS "$1.pdf" >> $buf
		if [ -f "${1}.pso.pdf" ]; then
			echo "OK!"
			mv "${1}.pso.pdf" "${1}.pdf"
		else
			echo "FAILED!"
		fi
	fi
	rm $buf
}

exists lualatex
exists biber
if ! exists pdfsizeopt 1; then
	echo "Not running pdfsizeopt for documentation compression."
fi

for x in [a-z][a-z].tex; do
	lbll ${x/.tex/}
done

lbll main
mv main.pdf UsersGuide.pdf
