/**
 * Accept only an explicit server-owned public-endpoint declaration.
 * Never pass a request body, header, query or client principal here.
 * Protected access remains denied until backend policy evaluation is implemented.
 */
export function isExplicitlyPublicEndpoint(serverMetadata: unknown): serverMetadata is true {
  return serverMetadata === true;
}
