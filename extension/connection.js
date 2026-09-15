/* Shared origin validation. Credentials are scoped to exactly this origin. */
function netraOrigin(value) {
    const url = new URL(value);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if ((url.protocol !== "https:" && !(local && url.protocol === "http:")) ||
        url.username || url.password || url.search || url.hash || url.pathname !== "/") {
        throw new Error("Enter an HTTPS server address without a path or credentials.");
    }
    return url.origin;
}
