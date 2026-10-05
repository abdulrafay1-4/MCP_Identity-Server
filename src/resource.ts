/** RFC 8707: an absolute URI without a fragment. http is accepted so local development works. */
export function isValidResourceUri(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return false;
  }
  if (url.hash !== "") {
    return false;
  }
  return true;
}
