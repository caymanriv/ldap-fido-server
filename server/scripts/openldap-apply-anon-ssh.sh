#!/usr/bin/env sh
set -eu

LDAP_URI="${LDAP_URI:-ldap://host.docker.internal:389}"
CONFIG_DN="cn=admin,cn=config"
BASE_DN="${BASE_DN:-dc=example,dc=org}"
: "${LDAP_CONFIG_PASSWORD:?LDAP_CONFIG_PASSWORD is required}"

info() { printf "[openldap-config] %s\n" "$*"; }

# 1) Load openssh-lpk schema (idempotent)
info "Loading openssh-lpk schema (if not already present) ..."
if ldapsearch -LLL -x -H "$LDAP_URI" -D "$CONFIG_DN" -w "$LDAP_CONFIG_PASSWORD" \
  -b "cn=schema,cn=config" '(cn=openssh-lpk)' dn | grep -q '^dn:'; then
  info "Schema already present."
else
  set +e
  ldapadd -x -H "$LDAP_URI" -D "$CONFIG_DN" -w "$LDAP_CONFIG_PASSWORD" -f /ldif/openssh-lpk.ldif
  rc=$?
  set -e
  if [ "$rc" -eq 80 ]; then
    info "Schema attributes already exist; continuing."
  elif [ "$rc" -ne 0 ]; then
    echo "Failed to load schema, rc=$rc" >&2
    exit "$rc"
  else
    info "Schema loaded."
  fi
fi

# 2) Determine actual MDB database DN under cn=config
info "Discovering MDB database DN ..."
MDB_DN=$(ldapsearch -LLL -x -H "$LDAP_URI" -D "$CONFIG_DN" -w "$LDAP_CONFIG_PASSWORD" \
  -b "cn=config" '(objectClass=olcMdbConfig)' dn | awk '/^dn: /{print $2; exit}')
if [ -z "${MDB_DN:-}" ]; then
  echo "Failed to detect olcMdbConfig DN" >&2
  exit 1
fi
info "MDB DN: $MDB_DN"

# 3) Check if sshPublicKey ACL already exists
info "Checking existing olcAccess for sshPublicKey rule ..."
if ldapsearch -LLL -x -H "$LDAP_URI" -D "$CONFIG_DN" -w "$LDAP_CONFIG_PASSWORD" \
  -b "$MDB_DN" olcAccess | grep -Eqi 'to attrs=sshPublicKey'; then
  info "ACL for sshPublicKey already present."
fi

# 4) Ensure anonymous can see base DN and entries (disclose/search)
info "Ensuring anonymous can read base DN $BASE_DN and 'entry' for subtree ..."
if ! ldapsearch -LLL -x -H "$LDAP_URI" -D "$CONFIG_DN" -w "$LDAP_CONFIG_PASSWORD" -b "$MDB_DN" olcAccess | \
  grep -Eqi "to dn.base=\"$BASE_DN\""; then
  cat <<EOF | ldapmodify -x -H "$LDAP_URI" -D "$CONFIG_DN" -w "$LDAP_CONFIG_PASSWORD"
dn: $MDB_DN
changetype: modify
add: olcAccess
olcAccess: {0}to dn.base="$BASE_DN"
  by anonymous read
  by users read
EOF
  info "Added ACL to allow anonymous read on base DN $BASE_DN."
else
  info "ACL for base DN read already present."
fi

# 5) Ensure anonymous can read the 'entry' pseudo-attribute to disclose/search subtree
if ! ldapsearch -LLL -x -H "$LDAP_URI" -D "$CONFIG_DN" -w "$LDAP_CONFIG_PASSWORD" -b "$MDB_DN" olcAccess | \
  grep -Eqi "to dn.subtree=\"$BASE_DN\".*attrs=entry"; then
  cat <<EOF | ldapmodify -x -H "$LDAP_URI" -D "$CONFIG_DN" -w "$LDAP_CONFIG_PASSWORD"
dn: $MDB_DN
changetype: modify
add: olcAccess
olcAccess: {1}to dn.subtree="$BASE_DN" attrs=entry
  by anonymous read
  by users read
EOF
  info "Added ACL to allow anonymous read of 'entry' under $BASE_DN."
else
  info "ACL for entry disclose under subtree already present."
fi

# 6) Ensure anonymous can read sshPublicKey values in subtree
if ! ldapsearch -LLL -x -H "$LDAP_URI" -D "$CONFIG_DN" -w "$LDAP_CONFIG_PASSWORD" -b "$MDB_DN" olcAccess | \
  grep -Eqi "to attrs=sshPublicKey"; then
  info "Applying ACL to allow anonymous read of sshPublicKey ..."
  cat <<EOF | ldapmodify -x -H "$LDAP_URI" -D "$CONFIG_DN" -w "$LDAP_CONFIG_PASSWORD"
dn: $MDB_DN
changetype: modify
add: olcAccess
olcAccess: {2}to attrs=sshPublicKey
  by anonymous read
  by self read
  by users read
EOF
  info "ACL for sshPublicKey applied successfully."
else
  info "ACL for sshPublicKey already present; skipping."
fi
