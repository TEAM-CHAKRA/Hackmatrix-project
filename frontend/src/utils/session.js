// The submitted message is kept only in this browser tab (sessionStorage) so the
// report can highlight phrases even if the backend chooses not to store raw text.
// It is never sent anywhere except the initial investigation request.

const key = (id) => `cyberlens:msg:${id}`;

export function stashMessage(id, text) {
  try {
    sessionStorage.setItem(key(id), text);
  } catch {
    /* storage unavailable — highlighting falls back to backend-provided text */
  }
}

export function readStashedMessage(id) {
  try {
    return sessionStorage.getItem(key(id));
  } catch {
    return null;
  }
}

export function clearStashedMessage(id) {
  try {
    sessionStorage.removeItem(key(id));
  } catch {
    /* ignore */
  }
}
