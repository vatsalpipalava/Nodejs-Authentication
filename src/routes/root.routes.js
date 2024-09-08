import { Router } from "express";
import path from "path";
import { fileURLToPath } from "url";

const router = Router();

// Convert __filename and __dirname to ESM equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

router.route("^/$|/index(.html)?").get((req, res) => {
  res.sendFile(path.join(__dirname, "..", "..", "public", "views", "index.html"));
});

router.route("/favicon.ico").get((req, res) => {
  res.sendFile(
    path.join(__dirname, "..", "..", "public", "assets", "favicon.ico")
  );
});

export default router;
