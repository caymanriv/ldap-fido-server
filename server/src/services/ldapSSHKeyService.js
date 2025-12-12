import { Client, Change, Attribute } from 'ldapts';
import { findLdapUser } from '../utils/ldapClient.js';

export async function addSSHPublicKeyToLDAP({ username, opensshPublicKey }) {
  if (!username || !opensshPublicKey) {
    throw new Error('MISSING_PARAMS');
  }

  const adminUrl = process.env.LDAP_URL;
  const adminDN = process.env.LDAP_ADMIN_DN;
  const adminPassword = process.env.LDAP_ADMIN_PASSWORD;

  const client = new Client({
    url: adminUrl,
    tlsOptions: process.env.LDAP_TLS_REJECT_UNAUTHORIZED === 'false' ? { rejectUnauthorized: false } : undefined,
  });

  try {
    const user = await findLdapUser(username);
    if (!user) throw new Error('LDAP_USER_NOT_FOUND');

    await client.bind(adminDN, adminPassword);

    // Ensure objectClass ldapPublicKey is present (required for sshPublicKey attribute)
    try {
      const objectClasses = Array.isArray(user.objectClass)
        ? user.objectClass.map(String)
        : (user.objectClass ? [String(user.objectClass)] : []);
      if (!objectClasses.includes('ldapPublicKey')) {
        await client.modify(user.dn, [
          new Change({
            operation: 'add',
            modification: new Attribute({ type: 'objectClass', values: ['ldapPublicKey'] })
          })
        ]);
      }
    } catch (e) {
      // Ignore if already exists or cannot add; we'll try attribute ops next
    }

    // Prepare attribute
    const attr = new Attribute({ type: 'sshPublicKey', values: [opensshPublicKey] });
    // Try REPLACE first
    try {
      await client.modify(user.dn, [new Change({ operation: 'replace', modification: attr })]);
    } catch (e) {
      try {
        // Fallback to ADD when attribute does not exist
        await client.modify(user.dn, [new Change({ operation: 'add', modification: attr })]);
      } catch (e2) {
        // As a last resort, attempt to add objectClass then add attribute again
        try {
          await client.modify(user.dn, [
            new Change({
              operation: 'add',
              modification: new Attribute({ type: 'objectClass', values: ['ldapPublicKey'] })
            })
          ]);
        } catch {}
        await client.modify(user.dn, [new Change({ operation: 'add', modification: attr })]);
      }
    }

    return { dn: user.dn };
  } finally {
    try { await client.unbind(); } catch (e) {}
  }
}
