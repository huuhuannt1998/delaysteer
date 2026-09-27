// Strip host-specific absolute paths (which embed the account name) from files written under results/.
// matter.js prints its storage location and stack traces with absolute paths; the paper is under
// double-anonymous review, so every such prefix is rewritten to a repo-relative path.
// Usage: node sanitize.mjs <file-or-dir> [...]
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir, userInfo } from "node:os";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export function sanitizeText(text) {
    const repo = REPO.endsWith("/") ? REPO : REPO + "/";
    let out = text.split(`file://${repo}`).join("").split(repo).join("");
    out = out.split(REPO).join(".");
    const home = homedir();
    out = out.split(home).join("~");
    const user = userInfo().username;
    if (user && user.length > 2) out = out.replace(new RegExp(`\\b${user}\\b`, "g"), "user");
    return out;
}

export function sanitizePath(p) {
    const st = statSync(p);
    if (st.isDirectory()) {
        for (const f of readdirSync(p)) sanitizePath(join(p, f));
        return;
    }
    const before = readFileSync(p, "utf8");
    const after = sanitizeText(before);
    if (after !== before) writeFileSync(p, after);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    for (const p of process.argv.slice(2)) sanitizePath(p);
}
