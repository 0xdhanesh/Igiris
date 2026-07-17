export function revisionChanged(loadedRevision, observedRevision) {
  return Boolean(loadedRevision && observedRevision && loadedRevision !== observedRevision);
}
