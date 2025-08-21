#!/bin/bash

export CURRENT_VERSION=$(git tag --sort=-committerdate | head -1)
export PREVIOUS_VERSION=$(git tag --sort=-committerdate | head -2 | awk '{split($0, tags, "\n")} END {print tags[1]}')
export CHANGES=$(git log --pretty="- %s" $CURRENT_VERSION...$PREVIOUS_VERSION)

cat > debian/changelog <<EOF
kobra (${VERSION}) unstable; urgency=medium

${CHANGES}

 -- The Kowabunga Project <maintainers@kowabunga.cloud>  $(date -R)
EOF

sed -i 's%^-%  \*%g' debian/changelog
fakeroot debian/rules binary
