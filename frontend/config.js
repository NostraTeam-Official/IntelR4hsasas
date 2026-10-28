/* Local two-server testing uses port 8000; the host serves frontend and API together. */
if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
  window.INTELR4H_API = "http://127.0.0.1:8000";
} else {
  window.INTELR4H_API = window.location.origin;
}
