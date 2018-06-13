#!/bin/sh
#
# This code is licensed under the GPL version 2 or later.  See
# the COPYING file in the top-level directory.

substat=".git-submodule-status"

command=$1
shift
modules="$@"

test -z "$GIT" && GIT=git

error() {
    echo "$0: $*"
    echo
    echo "Unable to automatically checkout GIT submodules '$modules'."
    echo "If you require use of an alternative GIT binary (for example to"
    echo "enable use of a transparent proxy), then please specify it by"
    echo "running configure by with the '--with-git' argument. e.g."
    echo
    echo " $ ./configure --with-git='tsocks git'"
    echo
    exit 1
}

if test -z "$modules"
then
    test -e $substat || touch $substat
    exit 0
fi

if ! test -e ".git"
then
    echo "$0: unexpectedly called with submodules but no git checkout exists"
    exit 1
fi

case "$command" in
status)
    test -f "$substat" || exit 1
    trap "rm -f ${substat}.tmp" EXIT
    $GIT submodule status $modules > "${substat}.tmp"
    test $? -ne 0 && error "failed to query git submodule status"
    diff "${substat}" "${substat}.tmp" >/dev/null
    exit $?
    ;;
update)
    if ! [ -e $modules ]; then
	    $GIT submodule update --init $modules 1>/dev/null
	    test $? -ne 0 && error "failed to update modules"
	    
	    $GIT submodule status $modules > "${substat}"
	    test $? -ne 0 && error "failed to save git submodule status" >&2

    fi
    ;;
esac

exit 0
