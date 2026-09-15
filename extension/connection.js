/* Shared origin validation. Credentials are scoped to exactly this origin. */
const NETRA_DEFAULT_API_ORIGIN = "https://netra-mail.onrender.com";
const NETRA_DEFAULT_DASHBOARD_ORIGIN = "https://netra-mail-dashboard.onrender.com";

function netraOrigin(value) {
    const url = new URL(value);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if ((url.protocol !== "https:" && !(local && url.protocol === "http:")) ||
        url.username || url.password || url.search || url.hash || url.pathname !== "/") {
        throw new Error("Enter an HTTPS server address without a path or credentials.");
    }
    return url.origin;
}
