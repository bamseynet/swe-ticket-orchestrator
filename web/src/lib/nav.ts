/** Go to a page. A full navigation, so the page discovered for that path loads fresh. */
export function navigate(path: string): void {
  window.location.assign(path);
}
