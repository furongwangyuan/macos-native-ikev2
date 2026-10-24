/** This gate prevents accidental default production exposure. It does not authenticate users. */
export function privateGatewayConfigured(env, localDevelopment = false) {
  return localDevelopment === true || env?.FAMILY_VPN_PRIVATE_SITES_DEPLOYMENT === 'owner-private-confirmed';
}
