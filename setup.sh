#! /bin/bash

set -e
source common.sh
git submodule update --init --recursive

# common libraries
pip3 install virtualenv

get_python_version() {
    python_dir=$(dirname $(which python3))

    version=$(python3 --version)
    version=${version#Python *}
    version=${version%.*}
    if [ "$version" \> "3.7" ]; then
        echo "python3"
    else
        versions="3.8 3.9"
        for v in $versions; do
            version="python$v"
            ret=$(which $version)
            if [ ! -z "$ret" ]; then
                echo "$version"
                break
            fi
        done
    fi
}

version="$(get_python_version)"
if [ -z "$version" ]; then
    echo "error: did not found a python version >= 3.8" & exit 1
fi
echo "got python version $version"

virtualenv ${SYZGEN} --python=$(which $version)

# OS specific
install_darwin_dependency () {
    brew install ldid
    brew install clang-format
    brew install cmake

    # install jtool2
    if [[ ! -f "jtool2.tgz" ]]; then
        curl -o jtool2.tgz http://www.newosxbook.com/tools/jtool2.tgz
        mkdir jtool2
        tar -xzf jtool2.tgz -C jtool2
    fi

    # install demumble
    if [[ ! -f "demumble-mac.zip" ]]; then
        # OR wget --no-check-certificate --content-disposition 
        curl -LJO https://github.com/nico/demumble/releases/download/v1.2.2/demumble-mac.zip
        unzip -o -d libs/ demumble-mac.zip
    fi
}

install_linux_dependency () {
    sudo apt install clang-format flex bison libelf-dev libssl-dev
    cd hooks/linux/client
    make getfd
    cd ../../../
}

UNAME_S=$(uname -s)
case ${UNAME_S} in
    Linux)
        echo "Detect Linux OS"
        OS="linux"
        syzkaller_branch="syzgen"
        install_linux_dependency
    ;;
    Darwin)
        echo "Detect Darwin OS"
        OS="darwin"
        syzkaller_branch="iokit"
        install_darwin_dependency
    ;;
    *)
        echo "unknown" && exit 1
    ;;
esac

# install golang
GO_VERSION="1.17.7"
GO_URL="https://dl.google.com/go/go${GO_VERSION}.${OS}-amd64.tar.gz"
# https://golang.org/doc/install
if [[ ! -f "go${GO_VERSION}.${OS}-amd64.tar.gz" ]]; then
    curl -o go${GO_VERSION}.${OS}-amd64.tar.gz ${GO_URL}
    tar -xzf go${GO_VERSION}.${OS}-amd64.tar.gz
fi

echo "GOROOT=\"${GOROOT}\"" >> $VIRTUAL_ENV
echo "export GOROOT" >> $VIRTUAL_ENV
echo "GOPATH=\"${GOPATH}\"" >> $VIRTUAL_ENV
echo "export GOPATH" >> $VIRTUAL_ENV
echo "PATH=${GOROOT}/bin:\$PATH" >> $VIRTUAL_ENV
echo "export PATH" >> $VIRTUAL_ENV

# install python dependencies
source ${VIRTUAL_ENV}
pip install -r requirements.txt

echo "installing custom cle..."
# install custom cle to support macOS driver
git clone git@github.com:angr/cle.git
cp cle.patch cle/
cd cle
git checkout -b dev 0eba8ae29f5f2386234dc252581bfce1b4994fac
git apply cle.patch
rm cle.patch
pip install .
cd ..

# install angr-targets
echo "installing custom angr-targets..."
git clone git@github.com:angr/angr-targets.git
cd angr-targets
pip install -e .
cd ..

cd libs
make -f Makefile.${UNAME_S}
cd ..

mkdir -p gopath/src/github.com/google
cd gopath/src/github.com/google
git clone -b ${syzkaller_branch} git@github.com:CvvT/syzkaller.git
cd syzkaller
make generate
make SOURCEDIR=tmp
cd ../../../../../

echo run "source ${SYZGEN}/bin/active" to set up the env
if [ $OS = "darwin" ]; then
    echo "Please use xcode to build kcov and macOS-tools"
fi
