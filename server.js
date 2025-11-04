require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static("public"));
app.use(
  session({
    secret: "tajnehaslo",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ===== KONFIG DISCORDA =====
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const adminIDs = ["962056433371840553"]; // 🔥 Twoje ID

passport.use(
  new DiscordStrategy(
    {
      clientID: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      callbackURL: REDIRECT_URI,
      scope: ["identify"],
    },
    (accessToken, refreshToken, profile, done) => done(null, profile)
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ===== BAZA JSON =====
const DB_PATH = path.join(__dirname, "database.json");
function loadDB() {
  if (!fs.existsSync(DB_PATH))
    return { users: {}, sessions: [], logs: [] };
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}
function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

// ===== AUTORYZACJA =====
function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/auth/discord");
}
function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && adminIDs.includes(req.user.id)) return next();
  res.status(403).send("Brak dostępu.");
}

// ===== ROUTES =====
app.get("/auth/discord", passport.authenticate("discord"));
app.get(
  "/auth/discord/callback",
  passport.authenticate("discord", { failureRedirect: "/" }),
  (req, res) => {
    const db = loadDB();
    const id = req.user.id;

    // Jeśli użytkownik nie istnieje, dodaj jako pracownika tylko jeśli admin to zrobi później
    if (!db.users[id]) {
      db.users[id] = { name: req.user.username, role: "none", stats: { plusy: 0, minusy: 0, robux: 0 } };
      saveDB(db);
    }

    // Sprawdź czy ma dostęp
    if (db.users[id].role === "pracownik") res.redirect("/dashboard.html");
    else if (adminIDs.includes(id)) res.redirect("/admin.html");
    else res.send("<h2>Brak dostępu – nie jesteś na liście pracowników.</h2>");
  }
);

app.get("/logout", (req, res) => {
  req.logout(() => res.redirect("/"));
});

// ===== API ADMIN =====

// Dodaj pracownika
app.post("/api/addWorker", ensureAdmin, (req, res) => {
  const { discordId } = req.body;
  const db = loadDB();

  if (!db.users[discordId]) {
    db.users[discordId] = { name: "Nowy pracownik", role: "pracownik", stats: { plusy: 0, minusy: 0, robux: 0 } };
    saveDB(db);
    res.json({ ok: true });
  } else {
    db.users[discordId].role = "pracownik";
    saveDB(db);
    res.json({ ok: true });
  }
});

// Utwórz sesję
app.post("/api/createSession", ensureAdmin, (req, res) => {
  const db = loadDB();
  const sessionNum = db.sessions.length + 1;
  db.sessions.push({ id: sessionNum, name: `Sesja ${sessionNum}`, attendance: {} });
  saveDB(db);
  res.json({ ok: true, sessionNum });
});

// Zaktualizuj obecność
app.post("/api/markAttendance", ensureAdmin, (req, res) => {
  const { sessionId, userId, status } = req.body;
  const db = loadDB();
  const session = db.sessions.find(s => s.id === sessionId);
  if (!session) return res.status(404).json({ error: "Nie znaleziono sesji" });

  session.attendance[userId] = status;
  db.logs.push({
    time: new Date().toISOString(),
    session: session.name,
    userId,
    status
  });
  saveDB(db);
  res.json({ ok: true });
});

// Dodaj plus/minus/wypłatę
app.post("/api/updateStats", ensureAdmin, (req, res) => {
  const { userId, field, value } = req.body;
  const db = loadDB();
  if (!db.users[userId]) return res.status(404).json({ error: "Nie znaleziono użytkownika" });
  db.users[userId].stats[field] += value;
  saveDB(db);
  res.json({ ok: true });
});

// Pobierz dane do panelu admina
app.get("/api/adminData", ensureAdmin, (req, res) => {
  res.json(loadDB());
});

// ===== PANEL PRACOWNIKA =====
app.get("/api/workerData", ensureAuth, (req, res) => {
  const db = loadDB();
  const id = req.user.id;
  const user = db.users[id];
  if (!user || user.role !== "pracownik") return res.status(403).json({ error: "Brak dostępu" });

  const sessions = db.sessions;
  const stats = user.stats;
  let obecnosci = 0;
  let razem = sessions.length;
  sessions.forEach(s => {
    if (s.attendance[id] === "obecny") obecnosci++;
  });
  const procent = razem > 0 ? Math.round((obecnosci / razem) * 100) : 0;

  res.json({ stats, procent, razem, obecnosci, sessions });
});

// ===== SERVER =====
const PORT = 3000;
app.listen(PORT, () => console.log(`✅ Serwer działa na http://localhost:${PORT}`));
