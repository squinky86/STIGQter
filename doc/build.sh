#!/bin/bash

function exists {
	which $1 > /dev/null 2> /dev/null
	ret=$?
	#program doesn't exist; check if aliased
	if [ $ret -gt 0 ]; then
		echo "Checking alias for $1..."
		type -a $1
		# > /dev/null 2> /dev/null
		ret=$?
	fi
	if [ $ret -gt 0 ]; then
		echo "Please install ${1} before building the documentation."
		if [ -z "$2" ]; then
			exit 1
		fi
		return 1
	fi
	return 0
}

function lbll {
	lualatex $1 && biber $1 && lualatex $1 && lualatex $1
	if exists pdfsizeopt 1; then
		OPTS=""
		if exists pngwolf 1; then
			OPTS="--use-image-optimizer=pngwolf"
		fi
		if exists advpng 1; then
			OPTS="${OPTS} --use-image-optimizer=advpng4"
		fi
		pdfsizeopt $OPTS $1.pdf
		if [ -f "${1}.pso.pdf" ]; then
			mv ${1}.pso.pdf ${1}.pdf
		fi
	fi
}

exists lualatex
exists biber
if ! exists pdfsizeopt 1; then
	echo "Warning, pdfsizeopt is not installed."
	sleep 5
fi

for x in [a-z][a-z].tex; do
	lbll ${x/.tex/}
done

lbll main
mv main.pdf UsersGuide.pdf
