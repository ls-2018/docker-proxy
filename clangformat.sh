#!/usr/bin/env bash

set -euf -o pipefail
usage() {
	echo "Usage: ${0} <src-dir> [-c/--check] [-h/--help]
    -c/--check
        Check the format but not perform actions
    -h/--help
        Show this page
    "
}

POSITIONAL=()
CHECK_ONLY=false
#OPTIONS=(-style=file --verbose --sort-includes -i)
OPTIONS=(-style=file --verbose -i)

while [[ $# -gt 0 ]]; do
	key="$1"
	case $key in
	-c | --check)
		CHECK_ONLY=true
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		POSITIONAL+=("$1")
		;;
	esac
	shift
done

if [[ ${#POSITIONAL[*]} -gt 0 ]]; then
	set -- "${POSITIONAL[*]}"
	FORMAT_DIR=$1
else
	usage
	exit 1
fi

if [[ ${CHECK_ONLY} == true ]]; then
	OPTIONS+=(-n -Werror)
	echo "Checking dir: ${1}"
else
	echo "Formating dir: ${1}"
fi

echo "pwd $(pwd)"
find "${FORMAT_DIR}" -type f \( -name '*.h' -or -name '*.hpp' -or -name '*.cpp' -or -name '*.c' -or -name '*.cc' \) -print | grep -v cmake-build-debug | grep -v CMakeFiles | xargs clang-format -style="file" -i ${OPTIONS[*]}
