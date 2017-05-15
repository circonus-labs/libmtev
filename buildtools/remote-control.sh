#!/bin/bash

set -e
cd `dirname $0`
cd ..

HOST="$1"
shift
REMOTE_DIR="~/libmtev"
if [[ $HOST = 'vagrant' ]]
then
    echo "Controlling Vagrant"
    SSH='vagrant ssh -- '
else
    echo "Controling host $HOST"
    SSH="ssh $HOST -t -- "
fi


CMDS=("cd $REMOTE_DIR; source ./buildtools/omnios/env.sh;")
function remotecmd {
    CMDS+=("printf '\n--------------------'")
    CMDS+=("printf '\n-- %s' \"$@\"")
    CMDS+=("printf '\n--------------------\n\n'")
    CMDS+=("$@")
}
function remoteexec {
    [ ${#CMDS[@]} -lt 2 ] && return
    # join commands
    GCMD=$(printf "%s\n" "${CMDS[@]}")
    $SSH "$GCMD"
    CMDS=("cd $REMOTE_DIR; source ./buildtools/omnios/env.sh;") # reset CMDS
}

function sync {
    remoteexec
    rsync --verbose --archive --compress --copy-links --no-owner --no-group \
          --exclude '.#*' \
          -e "$SSH" \
          $@
}

while [[ "$#" > 0 ]]
do
    echo "$1 ..."
    case $1 in
        --sync)
            sync --exclude .vagrant/ --exclude node_modules/ \
                 --delete \
                 ./ :$REMOTE_DIR
            ;;
        --update) # like sync but don't delete
            sync --exclude .vagrant/ --exclude node_modules/ \
                 ./ :$REMOTE_DIR
            ;;
        --git-clean)
            remotecmd "git clean -qxdf"
            ;;
        --git-reset)
            shift
            remotecmd "git reset --hard HEAD"
            ;;
        --install-dependencies)
            remotecmd 'sudo ./buildtools/omnios/dependencies.sh'
            ;;
        --configure)
            remotecmd './buildtools/omnios/configure.sh'
            ;;
        --build)
            remotecmd './buildtools/omnios/make.sh'
            ;;
        --install)
            remotecmd 'sudo ./buildtools/omnios/install.sh'
            ;;
        --rebuild)
            remotecmd './buildtools/omnios/build.sh'
            ;;
        --)
            shift
            remotecmd $@
            remoteexec
            exit $?
            ;;
        *)
            echo "unknown argument $1"
            exit 1
            ;;
    esac;
    shift
done

remoteexec
