#!/usr/bin/env sh
set -eu

LDAP_HOST_URI=${LDAP_HOST_URI:-ldap://host.docker.internal:389}
LDAP_ADMIN_DN=${LDAP_ADMIN_DN:-cn=admin,dc=example,dc=org}
LDAP_ADMIN_PASSWORD=${LDAP_ADMIN_PASSWORD:-adminpassword}
BASE_DN=${BASE_DN:-dc=example,dc=org}
LDIF_PATH=${LDIF_PATH:-/ldif/base-dit.ldif}

# Check if base DN exists
if ldapsearch -LLL -x -H "$LDAP_HOST_URI" -b "$BASE_DN" -s base "(objectClass=*)" dn >/dev/null 2>&1; then
  echo "Base DN '$BASE_DN' already exists. Skipping seed."
  exit 0
fi

echo "Base DN '$BASE_DN' not found. Seeding from $LDIF_PATH ..."
set +e
ldapadd -x -H "$LDAP_HOST_URI" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f "$LDIF_PATH"
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  echo "Base DN '$BASE_DN' created successfully."
  exit 0
elif [ "$rc" -eq 68 ]; then
  echo "Base DN '$BASE_DN' already exists (rc=68). Treating as success."
  exit 0
else
  echo "Failed to seed base DN '$BASE_DN' (rc=$rc)" >&2
  exit "$rc"
fi
