#!/usr/bin/env bash
# Publishes the files in dist/ as the Gitea release of the tag being built: creates the release (or
# takes the one already there, e.g. made by hand with notes) and replaces assets of the same name.
# Needs GITEA_TOKEN, GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_REF_NAME (set by Gitea Actions).
set -euo pipefail

tag=$GITHUB_REF_NAME
api="$GITHUB_SERVER_URL/api/v1/repos/$GITHUB_REPOSITORY"
auth=(-H "Authorization: token $GITEA_TOKEN")

# notes: the commits since the previous tag (all of them for the first one)
prev=$(git describe --tags --abbrev=0 "$tag^" 2>/dev/null || true)
range=${prev:+$prev..}$tag
{
	echo "${RELEASE_INTRO:-Сборки для Linux (статические, x86_64 и aarch64) и Windows (x86_64).}"
	echo "Проверка: \`sha256sum -c SHA256SUMS\`."
	echo
	echo "## Изменения${prev:+ с $prev}"
	echo
	git log -n 100 --no-merges --format='* %s' "$range"
} >notes.md

# a tag with a suffix (v1.2.0-rc1) is a pre-release
pre=false
[[ $tag == *-* ]] && pre=true

body=$(python3 -c 'import json,sys; print(json.dumps({"tag_name": sys.argv[1], "name": sys.argv[1], "body": open("notes.md").read(), "prerelease": sys.argv[2] == "true"}))' "$tag" "$pre")
id=$(curl -sf "${auth[@]}" "$api/releases/tags/$tag" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null || true)
if [[ -z $id ]]; then
	id=$(curl -sf "${auth[@]}" -H 'Content-Type: application/json' -d "$body" "$api/releases" |
		python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
	echo "release $tag created ($id)"
else
	echo "release $tag exists ($id): adding files"
fi

existing=$(curl -sf "${auth[@]}" "$api/releases/$id/assets")
for f in dist/*; do
	name=$(basename "$f")
	old=$(python3 -c 'import json,sys; print(next((str(a["id"]) for a in json.loads(sys.argv[1]) if a["name"] == sys.argv[2]), ""))' "$existing" "$name")
	[[ -n $old ]] && curl -sf "${auth[@]}" -X DELETE "$api/releases/$id/assets/$old"
	curl -sf "${auth[@]}" -F "attachment=@$f" "$api/releases/$id/assets?name=$name" >/dev/null
	echo "  $name"
done
