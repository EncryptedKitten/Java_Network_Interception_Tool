#!/bin/bash
# This script creates a new directory that only contains the contents that will be uploaded to git.
mkdir -p "Java_Network_Interception_Tool" || exit

cd "Java_Network_Interception_Tool" || exit

rm -rf "src" "lib" "build" "LICENSE.txt" "README.md" ./* || exit

cp -r "../src" "src" || exit
cp -r "../lib" "lib" || exit
cp -r "../manifold" "manifold" || exit
mkdir -p "build" || exit
cp -r "../build/jar" "build/jar" || exit

cp "../LICENSE.txt" "LICENSE.txt" || exit
cp "../README.md" "README.md" || exit
cp "../.gitignore" ".gitignore" || exit
cp ../*.py "." || exit
cp ../*.ini "." || exit
cp ../*.sh "." || exit

find . -name '.DS_Store' -delete
find . -name '._*' -delete