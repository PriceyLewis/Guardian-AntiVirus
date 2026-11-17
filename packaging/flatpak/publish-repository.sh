#!/bin/sh
# Add a Guardian bundle to the Flatpak repository on the gh-pages branch and push it.
# Run by .github/workflows/flatpak.yml for release tags. Needs GITHUB_TOKEN and
# GITHUB_REPOSITORY; GPG_PRIVATE_KEY, when set, signs the repository.
# PUBLISH=0 builds and checks a fresh repository without touching gh-pages.
set -eu

BUNDLE="$1"
APP=io.github.priceylewis.Guardian
OWNER="${GITHUB_REPOSITORY%%/*}"
NAME="${GITHUB_REPOSITORY#*/}"
URL="https://$(echo "$OWNER" | tr '[:upper:]' '[:lower:]').github.io/$NAME"
SITE="$(mktemp -d)/site"

command -v ostree >/dev/null 2>&1 || dnf install -y ostree

PUBLISH="${PUBLISH:-1}"
if [ "$PUBLISH" = 0 ] || ! git clone --quiet --depth 1 --branch gh-pages "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" "$SITE"; then
    mkdir -p "$SITE"
fi
rm -rf "$SITE/.git"
[ -f "$SITE/repo/config" ] || ostree init --repo="$SITE/repo" --mode=archive-z2

SIGN=""
GPG_LINE=""
if [ -n "${GPG_PRIVATE_KEY:-}" ]; then
    GNUPGHOME="$(mktemp -d)"
    export GNUPGHOME
    printf '%s\n' "$GPG_PRIVATE_KEY" | gpg --batch --import
    KEY="$(gpg --batch --list-secret-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')"
    SIGN="--gpg-sign=$KEY --gpg-homedir=$GNUPGHOME"
    GPG_LINE="GPGKey=$(gpg --batch --export "$KEY" | base64 -w 0)"
fi

# shellcheck disable=SC2086
flatpak build-import-bundle $SIGN "$SITE/repo" "$BUNDLE"
# Two builds are kept so an update can be rolled back; static deltas keep downloads small.
# shellcheck disable=SC2086
flatpak build-update-repo $SIGN --title="Guardian Antivirus" --default-branch=master \
    --generate-static-deltas --prune --prune-depth=2 "$SITE/repo"

cat > "$SITE/guardian.flatpakrepo" <<REPO
[Flatpak Repo]
Title=Guardian Antivirus
Url=$URL/repo/
Homepage=https://github.com/$GITHUB_REPOSITORY
Comment=Updates for Guardian Antivirus
${GPG_LINE}
REPO

cat > "$SITE/$APP.flatpakref" <<REF
[Flatpak Ref]
Name=$APP
Branch=master
Title=Guardian Antivirus
Url=$URL/repo/
RuntimeRepo=https://dl.flathub.org/repo/flathub.flatpakrepo
IsRuntime=false
${GPG_LINE}
REF
touch "$SITE/.nojekyll"

# Prove the repository installs and runs before publishing it.
VERIFY=""
[ -n "$SIGN" ] || VERIFY="--no-gpg-verify"
flatpak --user remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak --user remote-delete --force guardian-check >/dev/null 2>&1 || true
# shellcheck disable=SC2086
flatpak --user remote-add $VERIFY guardian-check "file://$SITE/repo"
flatpak --user install -y --noninteractive --reinstall guardian-check "$APP"
flatpak run "$APP" --version

if [ "$PUBLISH" = 0 ]; then
    echo "Repository built and installed from successfully; not published."
    exit 0
fi

# One commit holding only the current site keeps the branch small.
cd "$SITE"
git init --quiet --initial-branch=gh-pages
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add -A
git commit --quiet -m "Publish Flatpak repository for ${GITHUB_REF_NAME:-a release}"
git remote add origin "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
git push --force --quiet origin gh-pages
echo "Published $URL/repo/"
